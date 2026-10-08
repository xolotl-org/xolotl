#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::Path,
    process::{Command, Output},
};

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRoot, FederationRootKey,
    RootSignaturePurpose,
};

fn path(path: &Path) -> Result<&str> {
    path.to_str().context("non-UTF-8 test path")
}

fn run(args: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_xolotl-federation-key"))
        .args(args)
        .output()?)
}

fn success(output: &Output) -> Result<&str> {
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(std::str::from_utf8(&output.stdout)?)
}

fn failure(output: &Output) -> Result<()> {
    ensure!(!output.status.success());
    ensure!(output.stdout.is_empty());
    ensure!(!output.stderr.is_empty());
    Ok(())
}

fn issue(root: &Path, online: &Path, generation: &str, start: &str, end: &str) -> Result<Output> {
    run(&[
        "issue-online",
        "--root-dir",
        path(root)?,
        "--out-dir",
        path(online)?,
        "--generation",
        generation,
        "--not-before-ms",
        start,
        "--expires-ms",
        end,
    ])
}

fn mode(path: &Path) -> Result<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

fn no_staging_directory(parent: &Path) -> Result<bool> {
    for entry in fs::read_dir(parent)? {
        let name = entry?.file_name();
        if name
            .to_string_lossy()
            .starts_with(".xolotl-federation-key-")
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[test]
fn round_trip_private_files_signatures_and_script_output() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("offline-root");
    let online = directory.path().join("online-generation-7");
    let initialized = run(&["init-root", "--out-dir", path(&root)?])?;
    let root_stdout = success(&initialized)?;
    ensure!(root_stdout.starts_with("node_id=") && root_stdout.lines().count() == 1);
    ensure!(mode(&root)? == 0o700);
    for name in ["root.pk8", "root.bin"] {
        ensure!(mode(&root.join(name))? == 0o600);
    }
    let root_descriptor = fs::read(root.join("root.bin"))?;
    let root_key = FederationRootKey::from_pkcs8(&fs::read(root.join("root.pk8"))?)?;
    let root_public = FederationRoot::decode(&root_descriptor)?;
    ensure!(root_key.root()?.encode() == root_descriptor);

    let issued = issue(&root, &online, "7", "100", "200")?;
    let issued_stdout = success(&issued)?;
    ensure!(issued_stdout.contains("generation=7\n"));
    ensure!(issued_stdout.contains("not_before_ms=100\n"));
    ensure!(issued_stdout.contains("expires_ms=200\n"));
    ensure!(issued_stdout.contains(root_stdout.trim_end()));
    ensure!(mode(&online)? == 0o700);
    for name in [
        "root.bin",
        "online.pk8",
        "online-authorization.bin",
        "online-authorization.sig",
    ] {
        ensure!(mode(&online.join(name))? == 0o600);
    }
    ensure!(!online.join("root.pk8").exists());
    ensure!(fs::read(online.join("root.bin"))? == root_descriptor);
    let authorization_bytes = fs::read(online.join("online-authorization.bin"))?;
    let authorization = FederationOnlineKeyAuthorization::decode(&authorization_bytes)?;
    let signature = fs::read(online.join("online-authorization.sig"))?;
    root_public.verify(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization_bytes,
        &signature,
    )?;
    let online_key = FederationOnlineKey::from_pkcs8(&fs::read(online.join("online.pk8"))?)?;
    ensure!(online_key.public_key() == authorization.public_key());
    let digest = data_encoding::HEXLOWER.encode(&Sha384::digest(&authorization_bytes));
    ensure!(issued_stdout.contains(&format!("authorization_sha384={digest}\n")));

    let inspected = run(&["inspect", "--dir", path(&online)?])?;
    ensure!(success(&inspected)? == issued_stdout);
    Ok(())
}

#[test]
fn rejects_overwrite_invalid_inputs_symlinks_permissions_and_tampering() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("root");
    let online = directory.path().join("online");
    success(&run(&["init-root", "--out-dir", path(&root)?])?)?;
    let original = fs::read(root.join("root.pk8"))?;
    failure(&run(&["init-root", "--out-dir", path(&root)?])?)?;
    ensure!(fs::read(root.join("root.pk8"))? == original);
    ensure!(no_staging_directory(directory.path())?);
    failure(&issue(&root, &online, "0", "100", "200")?)?;
    failure(&issue(&root, &online, "1", "200", "200")?)?;
    failure(&issue(&root, &online, "1", "300", "200")?)?;
    ensure!(!online.exists());

    let key = root.join("root.pk8");
    let actual = root.join("private-original.pk8");
    fs::rename(&key, &actual)?;
    symlink(&actual, &key)?;
    failure(&issue(&root, &online, "1", "100", "200")?)?;
    fs::remove_file(&key)?;
    fs::rename(&actual, &key)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644))?;
    failure(&issue(&root, &online, "1", "100", "200")?)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;

    let linked_parent = directory.path().join("linked-parent");
    symlink(directory.path(), &linked_parent)?;
    failure(&issue(
        &root,
        &linked_parent.join("online"),
        "1",
        "100",
        "200",
    )?)?;
    success(&issue(&root, &online, "1", "100", "200")?)?;
    let descriptor = fs::read(online.join("root.bin"))?;
    failure(&issue(&root, &online, "2", "100", "200")?)?;
    ensure!(fs::read(online.join("root.bin"))? == descriptor);
    ensure!(no_staging_directory(directory.path())?);

    let signature_path = online.join("online-authorization.sig");
    let mut signature = fs::read(&signature_path)?;
    signature[0] ^= 1;
    fs::write(&signature_path, &signature)?;
    failure(&run(&["inspect", "--dir", path(&online)?])?)?;
    signature[0] ^= 1;
    fs::write(&signature_path, &signature)?;
    let key_path = online.join("online.pk8");
    let other = directory.path().join("other-online");
    success(&issue(&root, &other, "2", "100", "200")?)?;
    fs::copy(other.join("online.pk8"), &key_path)?;
    failure(&run(&["inspect", "--dir", path(&online)?])?)?;
    Ok(())
}
