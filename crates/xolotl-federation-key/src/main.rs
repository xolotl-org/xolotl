//! Offline provisioning for the unreleased federation v1 ML-DSA-65 identity.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod secure_fs;

#[cfg(target_os = "linux")]
use std::{
    io::{self, Write as _},
    path::PathBuf,
};

#[cfg(target_os = "linux")]
use anyhow::{Context as _, Result, ensure};
#[cfg(target_os = "linux")]
use clap::{Arg, ArgMatches, Command, value_parser};
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha384};
#[cfg(target_os = "linux")]
use xolotl_federation::{
    FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRoot, FederationRootKey,
    RootSignaturePurpose,
};

#[cfg(target_os = "linux")]
const ROOT_KEY: &str = "root.pk8";
#[cfg(target_os = "linux")]
const ROOT_DESCRIPTOR: &str = "root.bin";
#[cfg(target_os = "linux")]
const ONLINE_KEY: &str = "online.pk8";
#[cfg(target_os = "linux")]
const AUTHORIZATION: &str = "online-authorization.bin";
#[cfg(target_os = "linux")]
const AUTHORIZATION_SIGNATURE: &str = "online-authorization.sig";

#[cfg(target_os = "linux")]
fn cli() -> Command {
    fn path(name: &'static str, help: &'static str) -> Arg {
        Arg::new(name)
            .long(name)
            .help(help)
            .required(true)
            .value_parser(value_parser!(PathBuf))
    }
    fn number(name: &'static str, help: &'static str) -> Arg {
        Arg::new(name)
            .long(name)
            .help(help)
            .required(true)
            .value_parser(value_parser!(u64))
    }
    Command::new("xolotl-federation-key")
        .about("Offline federation v1 ML-DSA-65 root and online-key provisioning")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init-root")
                .about("Create a new 0700 offline root directory")
                .arg(path(
                    "out-dir",
                    "New absolute directory for root.pk8 and root.bin",
                )),
        )
        .subcommand(
            Command::new("issue-online")
                .about("Sign one online key with an existing offline root")
                .arg(path("root-dir", "Existing private offline root directory"))
                .arg(path(
                    "out-dir",
                    "New absolute directory for four daemon identity files",
                ))
                .arg(number("generation", "Positive online-key generation"))
                .arg(number(
                    "not-before-ms",
                    "Inclusive Unix timestamp in milliseconds",
                ))
                .arg(number(
                    "expires-ms",
                    "Exclusive Unix timestamp in milliseconds",
                )),
        )
        .subcommand(
            Command::new("inspect")
                .about("Verify one four-file online identity and print its public facts")
                .arg(path("dir", "Existing private online identity directory")),
        )
}

#[cfg(target_os = "linux")]
fn required_path<'a>(matches: &'a ArgMatches, name: &str) -> Result<&'a PathBuf> {
    matches
        .get_one::<PathBuf>(name)
        .with_context(|| format!("missing --{name}"))
}

#[cfg(target_os = "linux")]
fn required_number(matches: &ArgMatches, name: &str) -> Result<u64> {
    matches
        .get_one::<u64>(name)
        .copied()
        .with_context(|| format!("missing --{name}"))
}

#[cfg(target_os = "linux")]
fn print_root(root: &FederationRoot) -> Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "node_id={}",
        data_encoding::HEXLOWER.encode(root.node_id().as_bytes())
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn print_online(
    root: &FederationRoot,
    authorization: &FederationOnlineKeyAuthorization,
) -> Result<()> {
    let encoded = authorization.encode();
    let digest = Sha384::digest(&encoded);
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "node_id={}",
        data_encoding::HEXLOWER.encode(root.node_id().as_bytes())
    )?;
    writeln!(
        stdout,
        "authorization_sha384={}",
        data_encoding::HEXLOWER.encode(&digest)
    )?;
    writeln!(stdout, "generation={}", authorization.generation())?;
    writeln!(stdout, "not_before_ms={}", authorization.not_before_ms())?;
    writeln!(stdout, "expires_ms={}", authorization.expires_ms())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn init_root(matches: &ArgMatches) -> Result<()> {
    let destination = required_path(matches, "out-dir")?;
    let signing_key = FederationRootKey::generate()?;
    let root = signing_key.root()?;
    let descriptor = root.encode();
    let pkcs8 = signing_key.to_pkcs8()?;
    secure_fs::publish_new_directory(
        destination,
        &[(ROOT_KEY, pkcs8.as_ref()), (ROOT_DESCRIPTOR, &descriptor)],
    )?;
    print_root(&root)
}

#[cfg(target_os = "linux")]
fn issue_online(matches: &ArgMatches) -> Result<()> {
    let source = required_path(matches, "root-dir")?;
    let destination = required_path(matches, "out-dir")?;
    ensure!(
        source != destination,
        "root and online directories must differ"
    );
    let source = secure_fs::open_private_directory(source)?;
    let root_pkcs8 = secure_fs::read_private_file(&source, ROOT_KEY, 64 * 1024)?;
    let descriptor =
        secure_fs::read_private_file(&source, ROOT_DESCRIPTOR, FederationRoot::ENCODED_LEN as u64)?;
    let signing_key = FederationRootKey::from_pkcs8(&root_pkcs8)?;
    let root = FederationRoot::decode(&descriptor)?;
    ensure!(
        signing_key.root()?.encode() == *descriptor,
        "offline root key does not match root descriptor"
    );

    let online_key = FederationOnlineKey::generate()?;
    let authorization = FederationOnlineKeyAuthorization::new(
        online_key.public_key(),
        required_number(matches, "generation")?,
        required_number(matches, "not-before-ms")?,
        required_number(matches, "expires-ms")?,
    )?;
    let authorization_bytes = authorization.encode();
    let signature = signing_key.sign(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization_bytes,
    )?;
    let online_pkcs8 = online_key.to_pkcs8()?;
    secure_fs::publish_new_directory(
        destination,
        &[
            (ROOT_DESCRIPTOR, &descriptor),
            (ONLINE_KEY, online_pkcs8.as_ref()),
            (AUTHORIZATION, &authorization_bytes),
            (AUTHORIZATION_SIGNATURE, &signature),
        ],
    )?;
    print_online(&root, &authorization)
}

#[cfg(target_os = "linux")]
fn inspect(matches: &ArgMatches) -> Result<()> {
    let directory = secure_fs::open_private_directory(required_path(matches, "dir")?)?;
    let descriptor = secure_fs::read_private_file(
        &directory,
        ROOT_DESCRIPTOR,
        FederationRoot::ENCODED_LEN as u64,
    )?;
    let online_pkcs8 = secure_fs::read_private_file(&directory, ONLINE_KEY, 64 * 1024)?;
    let authorization_bytes = secure_fs::read_private_file(
        &directory,
        AUTHORIZATION,
        FederationOnlineKeyAuthorization::ENCODED_LEN as u64,
    )?;
    let signature = secure_fs::read_private_file(
        &directory,
        AUTHORIZATION_SIGNATURE,
        FederationRoot::SIGNATURE_LEN as u64,
    )?;
    let root = FederationRoot::decode(&descriptor)?;
    let authorization = FederationOnlineKeyAuthorization::decode(&authorization_bytes)?;
    ensure!(
        authorization.encode() == *authorization_bytes,
        "noncanonical online authorization"
    );
    root.verify(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization_bytes,
        &signature,
    )?;
    let online_key = FederationOnlineKey::from_pkcs8(&online_pkcs8)?;
    ensure!(
        online_key.public_key() == authorization.public_key(),
        "online private key does not match signed authorization"
    );
    print_online(&root, &authorization)
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("init-root", arguments)) => init_root(arguments),
        Some(("issue-online", arguments)) => issue_online(arguments),
        Some(("inspect", arguments)) => inspect(arguments),
        _ => anyhow::bail!("unsupported command"),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("offline federation key provisioning currently requires Linux")
}
