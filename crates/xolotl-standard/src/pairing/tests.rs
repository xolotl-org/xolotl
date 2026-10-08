use super::*;
use anyhow::{Context, bail, ensure};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use xolotl_source::ExternalInstallationMutation;
use xolotl_state::InMemoryBackend;
use xolotl_state::{StateCommit, StateMutation, StateResult, StateWrite, TaintedValue};
use xolotl_types::{
    EffectCapability, ExternalInstallationDef, Failure, IdentityRef, ProcessId, Transport,
    TrustLevel,
};

const TEST_VAULT_KEY: [u8; 32] = [0x91; 32];

#[test]
fn vault_sealing_keeps_secret_plaintext_in_one_allocation() -> anyhow::Result<()> {
    let key = [0x52; 32];
    ensure!(hash_secret_key(&key) == hash_secret(&hex(&key)));
    ensure!(display_secret_matches_key(&hex(&key), &key));
    let data = CredentialVaultData {
        pending: BTreeMap::from([(
            "pair".into(),
            PendingCredential {
                installation_id: "install".into(),
                installation_epoch: 4,
                intent_digest: [0; 32],
                key,
            },
        )]),
        active: BTreeMap::new(),
    };
    let mut plaintext = serialize_credential_vault(&data)?;
    let allocation = plaintext.as_ptr();
    let cipher = RandomizedNonceKey::new(&AES_256_GCM_SIV, &TEST_VAULT_KEY)
        .map_err(|_error| anyhow::anyhow!("invalid test key"))?;
    encrypt_credential_vault(&cipher, &mut plaintext)?;
    ensure!(plaintext.as_ptr() == allocation);
    let opened: CredentialVaultData =
        serde_json::from_slice(decrypt_credential_vault(&cipher, &mut plaintext)?)?;
    ensure!(
        opened
            .pending
            .get("pair")
            .is_some_and(|pending| pending.key == key)
    );
    Ok(())
}

#[test]
fn durable_pairing_credentials_survive_restart_and_fence_incarnations() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("external-credentials");
    let first = PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?;
    let old_key = [0x31; 32];
    first.persist_pending("pair-old", "install", 7, [0; 32], old_key)?;
    let old_generation =
        first.issue_credential("pair-old", "install", 7, &hash_secret(&hex(&old_key)), 0)?;
    ensure!(old_generation == 1);
    ensure!(
        first.issue_credential("pair-old", "install", 7, &hash_secret(&hex(&old_key)), 0)?
            == old_generation,
        "retry after a State write failure must reuse the issued generation",
    );
    let stored = std::fs::read(&path)?;
    ensure!(stored.starts_with(VAULT_MAGIC));
    ensure!(stored[VAULT_MAGIC.len()] == VAULT_FORMAT);
    ensure!(
        !stored
            .windows(b"pair-old".len())
            .any(|part| part == b"pair-old")
    );
    ensure!(
        !stored
            .windows(b"install".len())
            .any(|part| part == b"install")
    );
    drop(first);

    let reopened = PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?;
    ensure!(reopened.credential("install", 7, 1) == Some(old_key));
    ensure!(reopened.credential("install", 8, 1).is_none());
    let new_key = [0x52; 32];
    reopened.persist_pending("pair-new", "install", 8, [0; 32], new_key)?;
    let new_generation =
        reopened.issue_credential("pair-new", "install", 8, &hash_secret(&hex(&new_key)), 5)?;
    ensure!(new_generation == 6);
    ensure!(
        reopened.issue_credential("pair-new", "install", 8, &hash_secret(&hex(&new_key)), 5)?
            == new_generation,
    );
    ensure!(reopened.credential("install", 7, 1).is_none());
    ensure!(reopened.credential("install", 8, 6) == Some(new_key));
    drop(reopened);
    ensure!(
        PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?.credential("install", 8, 6)
            == Some(new_key)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(std::fs::metadata(&path)?.permissions().mode() & 0o077 == 0);
    }
    Ok(())
}

#[test]
fn encrypted_pairing_vault_rejects_plaintext_wrong_key_and_tampering() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("external-credentials");
    let vault = PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?;
    vault.persist_pending("pair", "install", 4, [0; 32], [0x71; 32])?;
    drop(vault);
    let original = std::fs::read(&path)?;
    ensure!(PairingDisplayEdge::open(&path, &[0x92; 32]).is_err());

    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    std::fs::write(&path, tampered)?;
    ensure!(PairingDisplayEdge::open(&path, &TEST_VAULT_KEY).is_err());

    std::fs::write(&path, &original[..original.len() - 1])?;
    ensure!(PairingDisplayEdge::open(&path, &TEST_VAULT_KEY).is_err());

    std::fs::write(&path, br#"{"pending":{},"active":{}}"#)?;
    ensure!(PairingDisplayEdge::open(&path, &TEST_VAULT_KEY).is_err());

    std::fs::write(&path, original)?;
    ensure!(PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?.has_pending("pair")?);
    Ok(())
}

#[cfg(unix)]
#[test]
fn pairing_vault_rejects_symlink_and_shared_permissions() -> anyhow::Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("external-credentials");
    let vault = PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?;
    vault.persist_pending("pair", "install", 4, [0; 32], [0x71; 32])?;
    drop(vault);
    let link = dir.path().join("linked-credentials");
    symlink(&path, &link)?;
    ensure!(PairingDisplayEdge::open(&link, &TEST_VAULT_KEY).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
    ensure!(PairingDisplayEdge::open(&path, &TEST_VAULT_KEY).is_err());
    Ok(())
}

#[test]
fn uncertain_vault_fails_closed_until_reopened() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("external-credentials");
    let vault = PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?;
    let key = [0x39; 32];
    vault.persist_pending("pair", "install", 4, [0; 32], key)?;
    ensure!(vault.issue_credential("pair", "install", 4, &hash_secret(&hex(&key)), 0)? == 1);
    vault.credentials.lock().uncertain = true;
    ensure!(vault.credential("install", 4, 1).is_none());
    ensure!(
        vault
            .persist_pending("next", "install", 4, [0; 32], [0x22; 32])
            .is_err()
    );
    drop(vault);
    ensure!(
        PairingDisplayEdge::open(&path, &TEST_VAULT_KEY)?.credential("install", 4, 1) == Some(key)
    );
    Ok(())
}

fn ctx() -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
}

fn driver() -> (PairingDriver, Backend) {
    let (state, owner) = InMemoryBackend::new().into_source_parts();
    (PairingDriver::new(state.clone(), Some(owner)), state)
}

#[tokio::test]
async fn revocation_floor_rejects_mismatched_or_invalid_state() -> anyhow::Result<()> {
    let (driver, state) = driver();
    let path = PairingDriver::revoke_path("install")?;
    ensure!(driver.credential_generation_floor("install").await? == 0);
    for (id, status, floor) in [
        ("other", STATE_REVOKED, 1),
        ("install", STATE_APPROVED, 1),
        ("install", STATE_REVOKED, 0),
    ] {
        state
            .write_set(
                &path,
                Value::map(BTreeMap::from([
                    ("installation_id".into(), Value::string(id.into())),
                    ("state".into(), Value::string(status.into())),
                    ("credential_generation_floor".into(), Value::integer(floor)),
                ])),
            )
            .await?;
        ensure!(driver.credential_generation_floor("install").await.is_err());
    }
    state
        .write_set(
            &path,
            Value::map(BTreeMap::from([
                ("installation_id".into(), Value::string("install".into())),
                ("state".into(), Value::string(STATE_REVOKED.into())),
                ("credential_generation_floor".into(), Value::integer(2)),
            ])),
        )
        .await?;
    ensure!(driver.credential_generation_floor("install").await? == 2);
    Ok(())
}

struct CommitThenError {
    inner: Arc<InMemoryBackend>,
    fail_next: AtomicBool,
}

impl StateWrite for CommitThenError {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let committed = StateWrite::mutate(self.inner.as_ref(), path, mutation).await?;
            if self.fail_next.swap(false, Ordering::SeqCst) {
                Err(StateError::Backend("injected post-commit error".into()).into())
            } else {
                Ok(committed)
            }
        })
    }
}

struct FailBeforeCommit {
    inner: Arc<InMemoryBackend>,
    fail_next: AtomicBool,
}

impl StateWrite for FailBeforeCommit {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                Err(StateError::Backend("injected pre-commit error".into()).into())
            } else {
                StateWrite::mutate(self.inner.as_ref(), path, mutation).await
            }
        })
    }
}

struct OccupyBeforeCas {
    inner: Arc<InMemoryBackend>,
    armed: AtomicBool,
}

impl StateWrite for OccupyBeforeCas {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if self.armed.swap(false, Ordering::SeqCst) {
                StateWrite::mutate(
                    self.inner.as_ref(),
                    path,
                    StateMutation::Set(TaintedValue::pristine(Value::string("occupied".into()))),
                )
                .await?;
            }
            StateWrite::mutate(self.inner.as_ref(), path, mutation).await
        })
    }
}

fn expected_driver_error(
    result: Result<DriverOutput, DriverError>,
    label: &str,
) -> anyhow::Result<DriverError> {
    match result {
        Ok(outcome) => bail!("{label}: expected driver error, got {outcome:?}"),
        Err(error) => Ok(error),
    }
}

fn done_map(output: DriverOutput, label: &str) -> anyhow::Result<ValueMap> {
    match output.outcome {
        Outcome::Done(value) => value.into_map().context("expected record map"),
        other => bail!("{label}: expected map output, got {other:?}"),
    }
}

fn external_installation(id: &str, role: Role) -> anyhow::Result<ExternalInstallationDef> {
    let projection = match role {
        Role::Provider => {
            let provider_namespace = xolotl_types::sandboxed_provider_namespace_path(id)?;
            let search_effect = provider_namespace.clone().try_push("search")?.to_string();
            xolotl_types::ExternalProjectionDef {
                id: "provider".into(),
                role,
                namespace: Some(provider_namespace),
                provides: vec![EffectCapability::new(search_effect, Purity::Idempotent)],
                emits: None,
                version: 1,
            }
        }
        Role::Source => xolotl_types::ExternalProjectionDef {
            id: "source".into(),
            role,
            namespace: None,
            provides: vec![],
            emits: Some(xolotl_types::EventSource {
                sink: xolotl_types::sandboxed_source_event_sink_path(id, "source")
                    .context("build source sink path")?,
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 65_536,
                capacity: xolotl_types::external::StreamCapacity {
                    max_events: 1024,
                    on_overflow: xolotl_types::external::OverflowPolicy::DropOldest,
                },
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            version: 1,
        },
    };
    let def = ExternalInstallationDef {
        id: id.into(),
        platform: id.into(),
        transport: Transport::Stdio {
            command: Some(format!("/usr/bin/{id}-plugin")),
            args: vec![],
        },
        trust: TrustLevel::Sandboxed,
        config_schema: Value::null(),
        config: Value::null(),
        projections: vec![projection],
        version: 1,
    };
    Ok(def)
}

async fn install_external(driver: &PairingDriver, id: &str, role: Role) -> anyhow::Result<()> {
    let authority = driver
        .installations
        .as_ref()
        .context("installation authority missing")?;
    let result = authority
        .compare_install(external_installation(id, role)?, None)
        .await?;
    ensure!(
        matches!(result, ExternalInstallationMutation::Applied(Some(_))),
        "installation was not committed"
    );
    Ok(())
}

async fn lock_pairing_claim(
    state: &Backend,
    pairing_id: &str,
    requested_roles: &[&str],
    sas_verified: bool,
) -> anyhow::Result<()> {
    let path = PairingDriver::pairing_path(pairing_id).context("build pairing path")?;
    let mut record = state
        .read(&path)
        .await?
        .context("pairing record missing")?
        .as_map()
        .context("pairing record is not a map")?
        .clone();
    record.insert("sas_verified".into(), Value::boolean(sas_verified))?;
    record.insert(
        "requested_roles".into(),
        Value::list(
            requested_roles
                .iter()
                .map(|role| Value::string((*role).into()))
                .collect(),
        ),
    )?;
    state.write_set(&path, Value::from(record)).await?;
    Ok(())
}

#[test]
fn pairing_state_paths_reject_path_delimiters() -> anyhow::Result<()> {
    ensure!(
        PairingDriver::pairing_path("pair/bad").is_err(),
        "pairing id with delimiter was accepted"
    );
    ensure!(
        validate_id_segment("ext/bad", "installation_id").is_err(),
        "installation id with delimiter was accepted"
    );
    ensure!(
        PairingDriver::pairing_path("_hidden").is_err()
            && PairingDriver::pairing_path("-hidden").is_err(),
        "pairing id with an invalid first character was accepted"
    );
    ensure!(
        validate_id_segment("_hidden", "installation_id").is_err(),
        "installation id with an invalid first character was accepted"
    );
    ensure!(
        PairingDriver::session_path("ext", "provider/bad").is_err(),
        "role with delimiter was accepted"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_create_persists_hash_without_secret() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-1", Role::Provider).await?;
    let mut input = BTreeMap::new();
    input.insert("pairing_id".into(), Value::string("pair-1".into()));
    input.insert("installation_id".into(), Value::string("ext-1".into()));
    input.insert(
        "allowed_roles".into(),
        Value::list(vec![Value::string("provider".into())]),
    );
    let out = driver
        .call(
            MethodId::new(0),
            Value::map(input),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    let record = done_map(out, "create pairing")?;
    ensure!(
        record.get("state") == Some(&Value::string(STATE_CREATED.into())),
        "unexpected pairing state: {:?}",
        record.get("state")
    );
    ensure!(
        record.get("pairing_secret").is_none(),
        "pairing record exposed secret"
    );
    let pairing_path =
        Path::parse("state://kernel/external-pairings/pair-1").context("parse pairing path")?;
    let stored = state
        .read(&pairing_path)
        .await?
        .context("pairing record missing")?;
    ensure!(
        stored == Value::from(record),
        "stored pairing record did not match returned record"
    );

    let secret = driver
        .take_display_secret("pair-1")
        .context("display secret missing")?;
    ensure!(
        secret.len() == 64,
        "expected 64 hex chars, got {}",
        secret.len()
    );
    ensure!(
        secret.chars().all(|c| c.is_ascii_hexdigit()),
        "display secret was not hex"
    );
    ensure!(
        driver.take_display_secret("pair-1").is_none(),
        "display secret was readable more than once"
    );
    Ok(())
}

#[tokio::test]
async fn denied_intent_can_be_followed_by_independent_create() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-compose", Role::Provider).await?;
    let create = |pairing_id: &str, installation_id: &str| {
        Value::map(BTreeMap::from([
            ("pairing_id".into(), Value::string(pairing_id.into())),
            (
                "installation_id".into(),
                Value::string(installation_id.into()),
            ),
        ]))
    };
    driver
        .call(
            MethodId::new(0),
            create("pair-old", "ext-compose"),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    driver
        .call(
            MethodId::new(2),
            Value::map(BTreeMap::from([(
                "pairing_id".into(),
                Value::string("pair-old".into()),
            )])),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(driver.take_display_secret("pair-old").is_none());
    ensure!(
        driver
            .call(
                MethodId::new(0),
                create("pair-new", "missing"),
                OutputMode::Unary,
                &ctx()
            )
            .await
            .is_err()
    );
    let denied = state
        .read(&PairingDriver::pairing_path("pair-old")?)
        .await?
        .context("denied old intent missing")?;
    ensure!(denied.as_map().and_then(|m| field_str(m, "state")) == Some(STATE_DENIED));
    ensure!(
        state
            .read(&PairingDriver::pairing_path("pair-new")?)
            .await?
            .is_none()
    );
    let out = driver
        .call(
            MethodId::new(0),
            create("pair-new", "ext-compose"),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(matches!(out.outcome, Outcome::Done(_)));
    ensure!(driver.take_display_secret("pair-new").is_some());
    Ok(())
}

#[tokio::test]
async fn create_retry_matches_exact_intent_and_never_reissues_display() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-retry", Role::Provider).await?;
    let input = Value::map(BTreeMap::from([
        ("pairing_id".into(), Value::string("pair-retry".into())),
        ("installation_id".into(), Value::string("ext-retry".into())),
    ]));
    driver
        .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx())
        .await?;
    ensure!(driver.take_display_secret("pair-retry").is_some());
    driver
        .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx())
        .await?;
    ensure!(driver.take_display_secret("pair-retry").is_none());
    let path = PairingDriver::pairing_path("pair-retry")?;
    let mut progressed = state
        .read(&path)
        .await?
        .context("pairing missing")?
        .as_map()
        .context("pairing malformed")?
        .clone();
    progressed.insert("sas_verified".into(), Value::boolean(true))?;
    state.write_set(&path, Value::from(progressed)).await?;
    ensure!(
        driver
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn post_commit_create_error_keeps_key_for_exact_retry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault_path = dir.path().join("credentials");
    let (base, owner) = InMemoryBackend::new().into_source_parts();
    let fault = Arc::new(CommitThenError {
        inner: owner.clone(),
        fail_next: AtomicBool::new(true),
    });
    let state = base.with_write(fault.clone());
    let driver = PairingDriver::with_display_edge(
        state.clone(),
        PairingDisplayEdge::open(&vault_path, &TEST_VAULT_KEY)?,
        Some(owner.clone()),
    );
    install_external(&driver, "ext-unknown", Role::Provider).await?;
    let input = Value::map(BTreeMap::from([
        ("pairing_id".into(), Value::string("pair-unknown".into())),
        (
            "installation_id".into(),
            Value::string("ext-unknown".into()),
        ),
    ]));
    ensure!(
        driver
            .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx())
            .await
            .is_err()
    );
    ensure!(
        state
            .read(&PairingDriver::pairing_path("pair-unknown")?)
            .await?
            .is_some()
    );
    ensure!(driver.display_edge.has_pending("pair-unknown")?);
    driver
        .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx())
        .await?;
    ensure!(driver.take_display_secret("pair-unknown").is_some());
    drop(driver);

    let reopened = PairingDriver::with_display_edge(
        state.clone(),
        PairingDisplayEdge::open(&vault_path, &TEST_VAULT_KEY)?,
        Some(owner),
    );
    reopened
        .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
        .await?;
    ensure!(reopened.take_display_secret("pair-unknown").is_none());
    let deny = Value::map(BTreeMap::from([(
        "pairing_id".into(),
        Value::string("pair-unknown".into()),
    )]));
    fault.fail_next.store(true, Ordering::SeqCst);
    ensure!(
        reopened
            .call(MethodId::new(2), deny.clone(), OutputMode::Unary, &ctx())
            .await
            .is_err()
    );
    ensure!(reopened.display_edge.has_pending("pair-unknown")?);
    reopened
        .call(MethodId::new(2), deny, OutputMode::Unary, &ctx())
        .await?;
    ensure!(!reopened.display_edge.has_pending("pair-unknown")?);
    Ok(())
}

#[tokio::test]
async fn pre_commit_create_retry_cannot_change_original_intent() -> anyhow::Result<()> {
    let (base, owner) = InMemoryBackend::new().into_source_parts();
    let state = base.with_write(Arc::new(FailBeforeCommit {
        inner: owner.clone(),
        fail_next: AtomicBool::new(true),
    }));
    let driver = PairingDriver::with_display_edge(
        state.clone(),
        PairingDisplayEdge::default(),
        Some(owner.clone()),
    );
    let mut installation = external_installation("ext-intent", Role::Provider)?;
    installation
        .projections
        .extend(external_installation("ext-intent", Role::Source)?.projections);
    ensure!(matches!(
        owner.compare_install(installation, None).await?,
        ExternalInstallationMutation::Applied(Some(_))
    ));

    let input = |roles: &[&str], expires_at| {
        Value::map(BTreeMap::from([
            ("pairing_id".into(), Value::string("pair-intent".into())),
            ("installation_id".into(), Value::string("ext-intent".into())),
            (
                "allowed_roles".into(),
                Value::list(
                    roles
                        .iter()
                        .map(|role| Value::string((*role).into()))
                        .collect(),
                ),
            ),
            ("expires_at".into(), Value::integer(expires_at)),
        ]))
    };
    let original = input(&["provider"], 0);
    ensure!(
        driver
            .call(
                MethodId::new(0),
                original.clone(),
                OutputMode::Unary,
                &ctx()
            )
            .await
            .is_err()
    );
    ensure!(
        state
            .read(&PairingDriver::pairing_path("pair-intent")?)
            .await?
            .is_none()
    );
    ensure!(driver.display_edge.has_pending("pair-intent")?);
    for changed in [input(&["source"], 0), input(&["provider"], 42)] {
        let error = expected_driver_error(
            driver
                .call(MethodId::new(0), changed, OutputMode::Unary, &ctx())
                .await,
            "changed create intent",
        )?;
        ensure!(error.to_string().contains("another intent"));
        ensure!(
            state
                .read(&PairingDriver::pairing_path("pair-intent")?)
                .await?
                .is_none()
        );
    }
    driver
        .call(MethodId::new(0), original, OutputMode::Unary, &ctx())
        .await?;
    ensure!(driver.take_display_secret("pair-intent").is_some());
    ensure!(driver.take_display_secret("pair-intent").is_none());
    Ok(())
}

#[tokio::test]
async fn create_absent_cas_does_not_overwrite_competing_state() -> anyhow::Result<()> {
    let (base, owner) = InMemoryBackend::new().into_source_parts();
    let state = base.with_write(Arc::new(OccupyBeforeCas {
        inner: owner.clone(),
        armed: AtomicBool::new(true),
    }));
    let driver =
        PairingDriver::with_display_edge(state.clone(), PairingDisplayEdge::default(), Some(owner));
    install_external(&driver, "ext-conflict", Role::Provider).await?;
    let pairing_id = "pair-conflict";
    let input = Value::map(BTreeMap::from([
        ("pairing_id".into(), Value::string(pairing_id.into())),
        (
            "installation_id".into(),
            Value::string("ext-conflict".into()),
        ),
    ]));
    ensure!(
        driver
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .is_err()
    );
    ensure!(
        state
            .read(&PairingDriver::pairing_path(pairing_id)?)
            .await?
            == Some(Value::string("occupied".into()))
    );
    ensure!(!driver.display_edge.has_pending(pairing_id)?);
    ensure!(driver.take_display_secret(pairing_id).is_none());
    Ok(())
}

#[tokio::test]
async fn deny_retry_cleans_orphaned_pending_credential() -> anyhow::Result<()> {
    let (driver, state) = driver();
    let pairing_id = "pair-orphan";
    driver
        .display_edge
        .persist_pending(pairing_id, "ext-orphan", 1, [0; 32], [0x35; 32])?;
    let input = Value::map(BTreeMap::from([(
        "pairing_id".into(),
        Value::string(pairing_id.into()),
    )]));
    driver
        .call(MethodId::new(2), input.clone(), OutputMode::Unary, &ctx())
        .await?;
    ensure!(!driver.display_edge.has_pending(pairing_id)?);
    let denied = state
        .read(&PairingDriver::pairing_path(pairing_id)?)
        .await?
        .context("denial tombstone missing")?;
    ensure!(denied.as_map().and_then(|m| field_str(m, "state")) == Some(STATE_DENIED));
    driver
        .call(MethodId::new(2), input, OutputMode::Unary, &ctx())
        .await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_approvals_leave_session_bound_to_latest_issued_credential() -> anyhow::Result<()>
{
    let (driver, state) = driver();
    install_external(&driver, "ext-concurrent", Role::Provider).await?;
    for pairing_id in ["pair-a", "pair-b"] {
        driver
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::from([
                    ("pairing_id".into(), Value::string(pairing_id.into())),
                    (
                        "installation_id".into(),
                        Value::string("ext-concurrent".into()),
                    ),
                ])),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        lock_pairing_claim(&state, pairing_id, &["provider"], true).await?;
    }
    let approve = |pairing_id: &'static str| async {
        driver
            .call(
                MethodId::new(1),
                Value::map(BTreeMap::from([(
                    "pairing_id".into(),
                    Value::string(pairing_id.into()),
                )])),
                OutputMode::Unary,
                &ctx(),
            )
            .await
    };
    let (first, second) = tokio::join!(approve("pair-a"), approve("pair-b"));
    first?;
    second?;
    let session = state
        .read(&PairingDriver::session_path("ext-concurrent", "provider")?)
        .await?
        .context("provider session missing")?;
    let session = session.as_map().context("provider session malformed")?;
    let generation = session
        .get("credential_generation")
        .and_then(Value::as_int)
        .context("provider session generation missing")?;
    ensure!(generation == 2);
    let issued = driver.display_edge.credentials.lock();
    let active = issued
        .data
        .active
        .get("ext-concurrent")
        .context("active credential missing")?;
    ensure!(active.generation == 2);
    ensure!(session.get("pairing_id").and_then(Value::as_str) == Some(active.pairing_id.as_str()));
    Ok(())
}

#[tokio::test]
async fn pairing_create_rejects_inline_secret() -> anyhow::Result<()> {
    let (driver, _) = driver();
    let mut input = BTreeMap::new();
    input.insert("pairing_id".into(), Value::string("pair-secret".into()));
    input.insert("pairing_secret".into(), Value::string("secret".into()));
    let out = driver
        .call(
            MethodId::new(0),
            Value::map(input),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(
        matches!(out.outcome, Outcome::Fail(Failure::InvalidInput { .. })),
        "unexpected inline secret outcome: {out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_create_requires_installed_external_scope() -> anyhow::Result<()> {
    let (driver, _) = driver();
    let mut input = BTreeMap::new();
    input.insert("pairing_id".into(), Value::string("pair-missing".into()));
    input.insert(
        "installation_id".into(),
        Value::string("missing-ext".into()),
    );
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(0),
                Value::map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "create pairing without installation",
    )?;
    ensure!(
        matches!(err, DriverError::Other(_)),
        "unexpected missing installation error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn state_installation_mirror_cannot_authorize_pairing() -> anyhow::Result<()> {
    let (driver, state) = driver();
    let path = Path::parse("state://kernel/external-installations/forged")?;
    let forged: Value = serde_json::from_value(serde_json::to_value(external_installation(
        "forged",
        Role::Provider,
    )?)?)?;
    state.write_set(&path, forged).await?;
    let input = Value::map(BTreeMap::from([
        ("pairing_id".into(), Value::string("pair-forged".into())),
        ("installation_id".into(), Value::string("forged".into())),
    ]));
    let result = driver
        .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
        .await;
    ensure!(
        result.is_err(),
        "State installation mirror authorized pairing"
    );
    ensure!(
        state
            .read(&PairingDriver::pairing_path("pair-forged")?)
            .await?
            .is_none(),
        "rejected pairing left an intent"
    );
    Ok(())
}

#[tokio::test]
async fn installation_update_keeps_pairing_intent_when_role_remains() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-generation", Role::Provider).await?;
    let create = Value::map(BTreeMap::from([
        ("pairing_id".into(), Value::string("pair-generation".into())),
        (
            "installation_id".into(),
            Value::string("ext-generation".into()),
        ),
    ]));
    driver
        .call(MethodId::new(0), create, OutputMode::Unary, &ctx())
        .await?;
    lock_pairing_claim(&state, "pair-generation", &["provider"], true).await?;
    let authority = driver
        .installations
        .as_ref()
        .context("installation authority missing")?;
    let revision = authority
        .load_installation("ext-generation")
        .await?
        .context("installation missing")?
        .revision();
    let replaced = authority
        .compare_install(
            external_installation("ext-generation", Role::Provider)?,
            Some(revision),
        )
        .await?;
    ensure!(
        matches!(replaced, ExternalInstallationMutation::Applied(Some(_))),
        "replacement failed"
    );
    let approve = Value::map(BTreeMap::from([(
        "pairing_id".into(),
        Value::string("pair-generation".into()),
    )]));
    driver
        .call(MethodId::new(1), approve, OutputMode::Unary, &ctx())
        .await?;
    let session = PairingDriver::session_path("ext-generation", "provider")?;
    let session = state
        .read(&session)
        .await?
        .context("provider session missing")?;
    let session = session.as_map().context("provider session is not a map")?;
    let installation = authority
        .load_installation("ext-generation")
        .await?
        .context("installation missing")?;
    ensure!(
        session.get("installation_epoch")
            == Some(&Value::string(installation.installation_epoch.to_string())),
        "provider session did not bind the installed incarnation"
    );
    Ok(())
}

#[tokio::test]
async fn retired_then_reinstalled_external_cannot_reuse_old_pairing_intent() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-reinstalled", Role::Provider).await?;
    let create = Value::map(BTreeMap::from([
        (
            "pairing_id".into(),
            Value::string("pair-before-retire".into()),
        ),
        (
            "installation_id".into(),
            Value::string("ext-reinstalled".into()),
        ),
    ]));
    driver
        .call(MethodId::new(0), create, OutputMode::Unary, &ctx())
        .await?;
    lock_pairing_claim(&state, "pair-before-retire", &["provider"], true).await?;
    let authority = driver
        .installations
        .as_ref()
        .context("installation authority missing")?;
    let revision = authority
        .load_installation("ext-reinstalled")
        .await?
        .context("installation missing")?
        .revision();
    let retired = authority
        .compare_retire("ext-reinstalled", revision)
        .await?;
    ensure!(
        matches!(retired, ExternalInstallationMutation::Applied(None)),
        "retirement failed"
    );
    let reinstalled = authority
        .compare_install(
            external_installation("ext-reinstalled", Role::Provider)?,
            None,
        )
        .await?;
    ensure!(
        matches!(reinstalled, ExternalInstallationMutation::Applied(Some(_))),
        "reinstallation failed"
    );
    let approve = Value::map(BTreeMap::from([(
        "pairing_id".into(),
        Value::string("pair-before-retire".into()),
    )]));
    let result = driver
        .call(MethodId::new(1), approve, OutputMode::Unary, &ctx())
        .await;
    ensure!(
        matches!(result, Err(DriverError::Other(ref message)) if message.contains("retired or replaced")),
        "old intent approved after retirement and reinstall: {result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_create_rejects_unknown_identity_field() -> anyhow::Result<()> {
    let (driver, _) = driver();
    install_external(&driver, "ext-unknown-field", Role::Provider).await?;
    let mut input = BTreeMap::new();
    input.insert(
        "pairing_id".into(),
        Value::string("pair-unknown-field".into()),
    );
    input.insert(
        "installation_id".into(),
        Value::string("ext-unknown-field".into()),
    );
    input.insert(
        "connection_id".into(),
        Value::string("transport-conn".into()),
    );
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(0),
                Value::map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "create pairing with unknown identity field",
    )?;
    ensure!(
        matches!(err, DriverError::Other(_)),
        "unexpected unknown identity field error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_create_rejects_explicit_empty_allowed_roles() -> anyhow::Result<()> {
    let (driver, _) = driver();
    install_external(&driver, "ext-empty-role", Role::Provider).await?;
    let mut input = BTreeMap::new();
    input.insert("pairing_id".into(), Value::string("pair-empty-role".into()));
    input.insert(
        "installation_id".into(),
        Value::string("ext-empty-role".into()),
    );
    input.insert("allowed_roles".into(), Value::list(vec![]));
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(0),
                Value::map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "create pairing with empty allowed roles",
    )?;
    ensure!(
        matches!(err, DriverError::Other(_)),
        "unexpected empty allowed roles error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_create_rejects_malformed_optional_fields() -> anyhow::Result<()> {
    let (driver, _) = driver();
    install_external(&driver, "ext-malformed-optional", Role::Provider).await?;
    for (field, value) in [
        ("pairing_id", Value::integer(1)),
        ("manifest_platform", Value::integer(1)),
        ("expires_at", Value::string("never".into())),
        ("expires_at", Value::integer(-1)),
    ] {
        let mut input = BTreeMap::new();
        input.insert(
            "pairing_id".into(),
            Value::string(format!("pair-malformed-{field}")),
        );
        input.insert(
            "installation_id".into(),
            Value::string("ext-malformed-optional".into()),
        );
        input.insert(field.into(), value);
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(0),
                    Value::map(input),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "create pairing with malformed optional field",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected malformed optional field error: {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn approve_projects_provider_external_state() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-2", Role::Provider).await?;
    let mut create = BTreeMap::new();
    create.insert("pairing_id".into(), Value::string("pair-2".into()));
    create.insert("installation_id".into(), Value::string("ext-2".into()));
    create.insert(
        "allowed_roles".into(),
        Value::list(vec![Value::string("provider".into())]),
    );
    driver
        .call(
            MethodId::new(0),
            Value::map(create),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    lock_pairing_claim(&state, "pair-2", &["provider"], true).await?;
    let mut approve = BTreeMap::new();
    approve.insert("pairing_id".into(), Value::string("pair-2".into()));
    driver
        .call(
            MethodId::new(1),
            Value::map(approve),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    let session_path = Path::parse("state://kernel/external-sessions/ext-2/provider")
        .context("parse provider session path")?;
    let ext = state
        .read(&session_path)
        .await?
        .context("provider session missing")?;
    let m = ext.as_map().context("provider session is not a map")?;
    ensure!(
        m.get("state") == Some(&Value::string("ready".into())),
        "unexpected provider session state: {:?}",
        m.get("state")
    );
    ensure!(
        m.get("credential_generation") == Some(&Value::integer(1)),
        "unexpected credential generation: {:?}",
        m.get("credential_generation")
    );
    Ok(())
}

#[tokio::test]
async fn approve_rejects_malformed_persisted_security_fields() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-persisted-security", Role::Provider).await?;

    for (pairing_id, field, value) in [
        ("pair-missing-expiry", "expires_at", None),
        (
            "pair-bad-expiry",
            "expires_at",
            Some(Value::string("never".into())),
        ),
        ("pair-missing-generation", "credential_generation", None),
        (
            "pair-bad-generation",
            "credential_generation",
            Some(Value::string("0".into())),
        ),
    ] {
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::string(pairing_id.into()));
        create.insert(
            "installation_id".into(),
            Value::string("ext-persisted-security".into()),
        );
        driver
            .call(
                MethodId::new(0),
                Value::map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        lock_pairing_claim(&state, pairing_id, &["provider"], true).await?;

        let path = PairingDriver::pairing_path(pairing_id)
            .context("build pairing path for malformed record")?;
        let mut record = state
            .read(&path)
            .await?
            .context("pairing record missing")?
            .as_map()
            .context("pairing record is not a map")?
            .clone();
        match value {
            Some(value) => {
                record.insert(field.into(), value)?;
            }
            None => {
                record.remove(field);
            }
        }
        state.write_set(&path, Value::from(record)).await?;

        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::string(pairing_id.into()));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(1),
                    Value::map(approve),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "approve malformed persisted pairing record",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected malformed persisted record error: {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn deny_rejects_malformed_pairing_state() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-bad-state", Role::Provider).await?;
    let pairing_id = "pair-bad-deny";
    driver
        .call(
            MethodId::new(0),
            Value::map(BTreeMap::from([
                ("pairing_id".into(), Value::string(pairing_id.into())),
                (
                    "installation_id".into(),
                    Value::string("ext-bad-state".into()),
                ),
            ])),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    let path = PairingDriver::pairing_path(pairing_id)?;
    let mut record = state
        .read(&path)
        .await?
        .context("pairing record missing")?
        .as_map()
        .context("pairing record is not a map")?
        .clone();
    record.remove("state");
    state.write_set(&path, Value::from(record)).await?;
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(2),
                Value::map(BTreeMap::from([(
                    "pairing_id".into(),
                    Value::string(pairing_id.into()),
                )])),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "deny with malformed pairing state",
    )?;
    ensure!(matches!(err, DriverError::Other(_)));
    Ok(())
}

#[tokio::test]
async fn pairing_scope_can_come_from_multi_projection_installation() -> anyhow::Result<()> {
    let (driver, state) = driver();
    let install = xolotl_types::ExternalInstallationDef {
        id: "instant_messaging_platform".into(),
        platform: "instant_messaging_platform".into(),
        transport: Transport::Grpc { endpoint: None },
        trust: TrustLevel::Sandboxed,
        config_schema: Value::null(),
        config: Value::null(),
        projections: vec![
            xolotl_types::ExternalProjectionDef {
                id: "source".into(),
                role: Role::Source,
                namespace: None,
                provides: vec![],
                emits: Some(xolotl_types::EventSource {
                    sink: xolotl_types::sandboxed_source_event_sink_path(
                        "instant_messaging_platform",
                        "source",
                    )
                    .context("build source sink path")?,
                    purity: Purity::Effectful,
                    event_schema: None,
                    max_inline_payload_bytes: 65_536,
                    capacity: xolotl_types::external::StreamCapacity {
                        max_events: 1024,
                        on_overflow: xolotl_types::external::OverflowPolicy::DropOldest,
                    },
                    rate_limit: None,
                    commands: false,
                    command_schema: None,
                    command_result_schema: None,
                }),
                version: 1,
            },
            xolotl_types::ExternalProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(
                    Path::parse("effect://external-provider/instant_messaging_platform")
                        .context("parse provider namespace")?,
                ),
                provides: vec![EffectCapability::new(
                    "effect://external-provider/instant_messaging_platform/send_text",
                    Purity::Effectful,
                )],
                emits: None,
                version: 1,
            },
        ],
        version: 1,
    };
    let authority = driver
        .installations
        .as_ref()
        .context("installation authority missing")?;
    let result = authority.compare_install(install, None).await?;
    ensure!(
        matches!(result, ExternalInstallationMutation::Applied(Some(_))),
        "multi-projection installation was not committed"
    );

    let mut create = BTreeMap::new();
    create.insert(
        "pairing_id".into(),
        Value::string("pair-instant_messaging_platform".into()),
    );
    create.insert(
        "installation_id".into(),
        Value::string("instant_messaging_platform".into()),
    );
    create.insert(
        "allowed_roles".into(),
        Value::list(vec![
            Value::string("source".into()),
            Value::string("provider".into()),
        ]),
    );
    driver
        .call(
            MethodId::new(0),
            Value::map(create),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    lock_pairing_claim(
        &state,
        "pair-instant_messaging_platform",
        &["source", "provider"],
        true,
    )
    .await?;
    let mut approve = BTreeMap::new();
    approve.insert(
        "pairing_id".into(),
        Value::string("pair-instant_messaging_platform".into()),
    );
    driver
        .call(
            MethodId::new(1),
            Value::map(approve),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    let source_path =
        Path::parse("state://kernel/external-sessions/instant_messaging_platform/source")
            .context("parse source session path")?;
    ensure!(
        state.read(&source_path).await?.is_some(),
        "source session missing"
    );
    let provider_path =
        Path::parse("state://kernel/external-sessions/instant_messaging_platform/provider")
            .context("parse provider session path")?;
    ensure!(
        state.read(&provider_path).await?.is_some(),
        "provider session missing"
    );
    Ok(())
}

#[tokio::test]
async fn approve_requires_sas_verified() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-sas", Role::Provider).await?;
    let mut create = BTreeMap::new();
    create.insert("pairing_id".into(), Value::string("pair-sas".into()));
    create.insert("installation_id".into(), Value::string("ext-sas".into()));
    create.insert(
        "allowed_roles".into(),
        Value::list(vec![Value::string("provider".into())]),
    );
    driver
        .call(
            MethodId::new(0),
            Value::map(create),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    lock_pairing_claim(&state, "pair-sas", &["provider"], false).await?;
    let mut approve = BTreeMap::new();
    approve.insert("pairing_id".into(), Value::string("pair-sas".into()));
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(1),
                Value::map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "approve without sas verification",
    )?;
    ensure!(
        matches!(err, DriverError::Other(_)),
        "unexpected sas verification error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn approve_rejects_frontend_claim_fields() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-claim", Role::Provider).await?;
    let mut create = BTreeMap::new();
    create.insert("pairing_id".into(), Value::string("pair-claim".into()));
    create.insert("installation_id".into(), Value::string("ext-claim".into()));
    driver
        .call(
            MethodId::new(0),
            Value::map(create),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    lock_pairing_claim(&state, "pair-claim", &["provider"], true).await?;
    let mut approve = BTreeMap::new();
    approve.insert("pairing_id".into(), Value::string("pair-claim".into()));
    approve.insert("sas_verified".into(), Value::boolean(true));
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(1),
                Value::map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "approve with frontend claim fields",
    )?;
    ensure!(
        matches!(err, DriverError::Other(_)),
        "unexpected frontend claim error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn approve_rejects_roles_outside_allowed_set() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-role", Role::Provider).await?;
    let mut create = BTreeMap::new();
    create.insert("pairing_id".into(), Value::string("pair-role".into()));
    create.insert("installation_id".into(), Value::string("ext-role".into()));
    create.insert(
        "allowed_roles".into(),
        Value::list(vec![Value::string("provider".into())]),
    );
    driver
        .call(
            MethodId::new(0),
            Value::map(create),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    lock_pairing_claim(&state, "pair-role", &["source"], true).await?;
    let mut approve = BTreeMap::new();
    approve.insert("pairing_id".into(), Value::string("pair-role".into()));
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(1),
                Value::map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "approve roles outside allowed set",
    )?;
    ensure!(
        matches!(err, DriverError::Other(_)),
        "unexpected role claim error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn approve_terminalizes_expired_intent() -> anyhow::Result<()> {
    let (driver, state) = driver();
    install_external(&driver, "ext-exp", Role::Provider).await?;
    let mut create = BTreeMap::new();
    create.insert("pairing_id".into(), Value::string("pair-exp".into()));
    create.insert("installation_id".into(), Value::string("ext-exp".into()));
    create.insert("expires_at".into(), Value::integer(1));
    create.insert(
        "allowed_roles".into(),
        Value::list(vec![Value::string("provider".into())]),
    );
    driver
        .call(
            MethodId::new(0),
            Value::map(create),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    let mut approve = BTreeMap::new();
    approve.insert("pairing_id".into(), Value::string("pair-exp".into()));
    let err = expected_driver_error(
        driver
            .call(
                MethodId::new(1),
                Value::map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await,
        "approve expired intent",
    )?;
    ensure!(
        matches!(err, DriverError::Other(_)),
        "unexpected expired intent error: {err:?}"
    );
    let pairing_path = Path::parse("state://kernel/external-pairings/pair-exp")
        .context("parse expired pairing path")?;
    let stored = state
        .read(&pairing_path)
        .await?
        .context("expired pairing record missing")?;
    let state = stored
        .as_map()
        .context("expired pairing record is not a map")?
        .get("state");
    ensure!(
        state == Some(&Value::string(STATE_EXPIRED.into())),
        "expired pairing state was not terminalized"
    );
    Ok(())
}

#[tokio::test]
async fn revoke_writes_generation_floor() -> anyhow::Result<()> {
    let (driver, state) = driver();
    let mut input = BTreeMap::new();
    input.insert("installation_id".into(), Value::string("ext-4".into()));
    input.insert("credential_generation_floor".into(), Value::integer(7));
    driver
        .call(
            MethodId::new(3),
            Value::map(input),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    let revoke_path = Path::parse("state://kernel/external-credential-revocations/ext-4")
        .context("parse revocation path")?;
    let revoked = state
        .read(&revoke_path)
        .await?
        .context("revocation record missing")?;
    let m = revoked.as_map().context("revocation record is not a map")?;
    ensure!(
        m.get("state") == Some(&Value::string(STATE_REVOKED.into())),
        "unexpected revocation state: {:?}",
        m.get("state")
    );
    ensure!(
        m.get("credential_generation_floor") == Some(&Value::integer(7)),
        "unexpected generation floor: {:?}",
        m.get("credential_generation_floor")
    );
    Ok(())
}

#[tokio::test]
async fn revoke_covers_current_credential_and_never_lowers_floor() -> anyhow::Result<()> {
    let (driver, state) = driver();
    let key = [0x75; 32];
    driver
        .display_edge
        .persist_pending("pair-current", "ext-current", 1, [0; 32], key)?;
    ensure!(
        driver.display_edge.issue_credential(
            "pair-current",
            "ext-current",
            1,
            &hash_secret(&hex(&key)),
            3,
        )? == 4,
    );
    let revoke = |floor: Option<i64>| {
        let mut input = BTreeMap::from([(
            "installation_id".into(),
            Value::string("ext-current".into()),
        )]);
        if let Some(floor) = floor {
            input.insert("credential_generation_floor".into(), Value::integer(floor));
        }
        Value::map(input)
    };
    driver
        .call(MethodId::new(3), revoke(None), OutputMode::Unary, &ctx())
        .await?;
    ensure!(driver.credential_generation_floor("ext-current").await? == 4);
    ensure!(
        driver
            .call(MethodId::new(3), revoke(Some(3)), OutputMode::Unary, &ctx())
            .await
            .is_err()
    );
    ensure!(driver.credential_generation_floor("ext-current").await? == 4);
    driver
        .call(MethodId::new(3), revoke(Some(7)), OutputMode::Unary, &ctx())
        .await?;
    driver
        .call(MethodId::new(3), revoke(None), OutputMode::Unary, &ctx())
        .await?;
    ensure!(driver.credential_generation_floor("ext-current").await? == 7);
    let record = state
        .read(&PairingDriver::revoke_path("ext-current")?)
        .await?
        .context("revocation record missing")?;
    ensure!(
        record
            .as_map()
            .and_then(|record| record.get("credential_generation_floor"))
            == Some(&Value::integer(7))
    );
    Ok(())
}

#[tokio::test]
async fn revoke_rejects_invalid_generation_floor() -> anyhow::Result<()> {
    for floor in [
        Value::integer(0),
        Value::integer(-1),
        Value::string("7".into()),
    ] {
        let (driver, state) = driver();
        let mut input = BTreeMap::new();
        input.insert(
            "installation_id".into(),
            Value::string("ext-invalid-floor".into()),
        );
        input.insert("credential_generation_floor".into(), floor);

        let err = match driver
            .call(
                MethodId::new(3),
                Value::map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await
        {
            Ok(_) => bail!("revoke accepted invalid generation floor"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected revoke error: {err:?}"
        );
        let path = Path::parse("state://kernel/external-credential-revocations/ext-invalid-floor")
            .context("parse revoke path")?;
        let stored = state.read(&path).await.context("read revoke path")?;
        ensure!(stored.is_none(), "invalid revoke wrote state: {stored:?}");
    }
    Ok(())
}
