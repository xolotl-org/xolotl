//! Exercise WebAuthn with real ES256 assertions through the public host service.

#[path = "support/sealer.rs"]
mod sealer;

#[path = "support/pqc_key.rs"]
#[expect(
    dead_code,
    reason = "passkey evidence test only needs the public descriptor"
)]
mod pqc_key;

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::BigNum,
    bn::BigNumContext,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use xolotl_console::{
    AuthenticationEvidence, ConsoleAuthConfig, ConsoleConfig, ConsoleErrorCode, ConsoleService,
    ConsoleState, ConsoleWebAuthnConfig, LoginRequest, LoginResponse, PasskeyLoginBeginRequest,
    PasskeyLoginFinishRequest, PasskeyRegisterBeginRequest, PasskeyRegisterBeginResponse,
    PasskeyRegisterFinishRequest, PrimaryAuthentication, RootProvisioning, bootstrap_root_account,
    credentials::{CredentialOperation, CredentialRequest, CredentialResponse},
};
use xolotl_kernel::{Bootstrap, KernelBuilder, host::system_now_millis};
use xolotl_standard::{StandardConfig, install_standard};
use xolotl_state::{
    Backend, InMemoryBackend, StateBoundedRead, StateBoundedWrite, StateCommit, StateMutation,
    StateRead, StateResult, StateWrite,
};
use xolotl_types::{Path, TaintedValue, Value as StateValue};

const PASSWORD: &str = "9Zm$R6!yL2#vT8qWs4e";
const CREDENTIALS_PREFIX: &str = "state://vault/console/credentials/local/";

fn login_request() -> LoginRequest {
    LoginRequest {
        username: "root".into(),
        password: PASSWORD.into(),
        second_factor: None,
    }
}

struct TestService {
    service: ConsoleService,
    store: Arc<dyn xolotl_console::session_store::ConsoleSessionStore>,
}

impl std::ops::Deref for TestService {
    type Target = ConsoleService;
    fn deref(&self) -> &Self::Target {
        &self.service
    }
}

impl TestService {
    async fn sessions(&self) -> anyhow::Result<xolotl_console::session_store::SessionStorePage> {
        Ok(self
            .store
            .list(
                None,
                xolotl_console::session_store::SessionPageLimits {
                    rows: 256,
                    bytes: 1024 * 1024,
                },
            )
            .await?)
    }
}

async fn fixture(boot: Arc<Bootstrap>) -> anyhow::Result<(TestService, LoginResponse)> {
    install_standard(&boot, &StandardConfig::default())?;
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            password: Some(PASSWORD.into()),
            ..Default::default()
        },
    )
    .await?;
    let store = Arc::new(
        xolotl_console::session_store::MemoryConsoleSessionStore::new(
            xolotl_console::session_store::ConsoleSessionPolicy::default(),
        ),
    );
    let service = ConsoleService::new(ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(store.clone()),
            auth: ConsoleAuthConfig {
                credential_sealer: Some(crate::sealer::sealer()),
                webauthn: ConsoleWebAuthnConfig {
                    enabled: true,
                    rp_id: "console.local".into(),
                    rp_origin: "https://console.local".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )?);
    let session = service
        .login(login_request(), "test".into())
        .await?
        .into_session()
        .ok()
        .context("authenticated session")?;
    Ok((TestService { service, store }, session))
}

async fn root_credential_path(state: &Backend) -> anyhow::Result<Path> {
    let root = state
        .read(&Path::parse("state://kernel/console/users/root")?)
        .await?
        .context("root account")?;
    let account_id = root
        .as_map()
        .and_then(|fields| fields.get("account_id"))
        .and_then(StateValue::as_str)
        .context("root account instance")?;
    Ok(Path::parse(&format!("{CREDENTIALS_PREFIX}{account_id}"))?)
}

struct Authenticator {
    key: PKey<Private>,
    id: Vec<u8>,
    cose: Vec<u8>,
}

impl Authenticator {
    fn new() -> anyhow::Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        let (mut x, mut y, mut context) = (BigNum::new()?, BigNum::new()?, BigNumContext::new()?);
        key.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)?;
        // COSE EC2/P-256/ES256 map: {1:2, 3:-7, -1:1, -2:x, -3:y}.
        let mut cose = vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32];
        cose.extend(x.to_vec_padded(32)?);
        cose.extend([0x22, 0x58, 32]);
        cose.extend(y.to_vec_padded(32)?);
        Ok(Self {
            key: PKey::from_ec_key(key)?,
            id: Sha256::digest(&cose)[..16].to_vec(),
            cose,
        })
    }

    fn client_data(options: &Value, ceremony: &str, origin: &str) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"type": ceremony, "challenge": options["publicKey"]["challenge"],
            "origin": origin, "crossOrigin": false}),
        )?)
    }

    fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(b"console.local").to_vec();
        data.push(flags);
        data.extend(counter.to_be_bytes());
        data
    }

    fn registration(
        &self,
        begin: PasskeyRegisterBeginResponse,
        origin: &str,
    ) -> anyhow::Result<PasskeyRegisterFinishRequest> {
        let options = serde_json::to_value(begin.public_key)?;
        let client_data = Self::client_data(&options, "webauthn.create", origin)?;
        let mut auth_data = Self::auth_data(0x45, 0); // UP, UV, attested credential.
        auth_data.extend([0; 16]); // AAGUID for a test authenticator.
        auth_data.extend((self.id.len() as u16).to_be_bytes());
        auth_data.extend(&self.id);
        auth_data.extend(&self.cose);
        // A standard, unsigned "none" attestation: no trusted attestation is claimed.
        let mut attestation = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58".to_vec();
        attestation.push(u8::try_from(auth_data.len())?);
        attestation.extend(auth_data);
        Ok(PasskeyRegisterFinishRequest {
            challenge_id: begin.challenge_id,
            credential: serde_json::from_value(json!({"id": URL_SAFE_NO_PAD.encode(&self.id),
                "rawId": URL_SAFE_NO_PAD.encode(&self.id), "type":"public-key", "clientExtensionResults":{},
                "response": {"attestationObject":URL_SAFE_NO_PAD.encode(attestation),
                    "clientDataJSON":URL_SAFE_NO_PAD.encode(client_data)}}))?,
        })
    }

    fn assertion(
        &self,
        challenge: xolotl_console::PasskeyLoginBeginResponse,
        counter: u32,
    ) -> anyhow::Result<PasskeyLoginFinishRequest> {
        self.assertion_with_flags(challenge, counter, 0x05) // UP and UV.
    }

    fn assertion_with_flags(
        &self,
        challenge: xolotl_console::PasskeyLoginBeginResponse,
        counter: u32,
        flags: u8,
    ) -> anyhow::Result<PasskeyLoginFinishRequest> {
        let client_data = Self::client_data(
            &serde_json::to_value(challenge.public_key)?,
            "webauthn.get",
            "https://console.local",
        )?;
        let auth_data = Self::auth_data(flags, counter);
        let mut signed = auth_data.clone();
        signed.extend(Sha256::digest(&client_data));
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
        let signature = signer.sign_oneshot_to_vec(&signed)?;
        Ok(PasskeyLoginFinishRequest {
            username: "root".into(),
            challenge_id: challenge.challenge_id,
            credential: serde_json::from_value(json!({"id":URL_SAFE_NO_PAD.encode(&self.id),
                "rawId":URL_SAFE_NO_PAD.encode(&self.id), "type":"public-key", "clientExtensionResults":{},
                "response":{"authenticatorData":URL_SAFE_NO_PAD.encode(auth_data),
                    "clientDataJSON":URL_SAFE_NO_PAD.encode(client_data), "signature":URL_SAFE_NO_PAD.encode(signature),
                    "userHandle":null}}))?,
        })
    }
}

fn change(operation: CredentialOperation) -> CredentialRequest {
    CredentialRequest {
        username: None,
        operation,
    }
}

async fn begin(
    service: &ConsoleService,
    token: &str,
) -> anyhow::Result<PasskeyRegisterBeginResponse> {
    Ok(service
        .begin_passkey_registration(
            token,
            PasskeyRegisterBeginRequest {
                label: "Test authenticator".into(),
                display_name: None,
            },
            "test".into(),
        )
        .await?)
}

async fn challenge(
    service: &ConsoleService,
) -> anyhow::Result<xolotl_console::PasskeyLoginBeginResponse> {
    Ok(service
        .begin_passkey_login(
            PasskeyLoginBeginRequest {
                username: "root".into(),
            },
            "test".into(),
        )
        .await?)
}

fn replacement(response: CredentialResponse) -> anyhow::Result<LoginResponse> {
    match response {
        CredentialResponse::Updated {
            sessions_invalidated: true,
            session: Some(session),
        } => Ok(session),
        _ => anyhow::bail!("expected replacement session"),
    }
}

#[tokio::test]
async fn passkey_ceremonies_labels_revocation_and_epoch_binding() -> anyhow::Result<()> {
    let (service, session) = fixture(Arc::new(Bootstrap::in_memory())).await?;
    let authenticator = Authenticator::new()?;
    let invalid_origin = authenticator.registration(
        begin(&service, &session.token).await?,
        "https://attacker.example",
    )?;
    let error = service
        .finish_passkey_registration(&session.token, invalid_origin, "test".into())
        .await
        .err()
        .context("wrong origin")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    let other = service
        .login(login_request(), "test".into())
        .await?
        .into_session()
        .ok()
        .context("authenticated session")?;
    let pending = authenticator.registration(
        begin(&service, &session.token).await?,
        "https://console.local",
    )?;
    let error = service
        .finish_passkey_registration(&other.token, pending, "test".into())
        .await
        .err()
        .context("wrong session")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);

    let registered = service
        .finish_passkey_registration(
            &session.token,
            authenticator.registration(
                begin(&service, &session.token).await?,
                "https://console.local",
            )?,
            "test".into(),
        )
        .await?;
    ensure!(registered.session.authentication == session.authentication);
    ensure!(
        service
            .refresh(&session.token, "test".into())
            .await
            .is_err()
    );
    let assertion = authenticator.assertion(challenge(&service).await?, 1)?;
    let encoded = serde_json::to_vec(&assertion)?;
    let login = service
        .finish_passkey_login(assertion, "test".into())
        .await?;
    ensure!(login.authentication.mfa_level() == 2);
    ensure!(matches!(
        &login.authentication.primary,
        PrimaryAuthentication::PasskeyUv { credential_id, .. }
        if credential_id == &registered.credential_id
    ));
    ensure!(login.authentication.secondary.is_none());
    ensure!(
        service
            .finish_passkey_login(serde_json::from_slice(&encoded)?, "test".into())
            .await
            .is_err()
    );
    let renamed = service
        .credentials(
            &login.token,
            change(CredentialOperation::RenamePasskey {
                credential_id: registered.credential_id.clone(),
                label: "Travel key".into(),
            }),
            "test".into(),
        )
        .await?;
    ensure!(matches!(
        renamed,
        CredentialResponse::Updated {
            sessions_invalidated: false,
            session: None
        }
    ));
    let status = service
        .credentials(
            &login.token,
            change(CredentialOperation::Status {}),
            "test".into(),
        )
        .await?;
    ensure!(
        matches!(status, CredentialResponse::Current { ref passkeys, .. }
        if passkeys.len() == 1 && passkeys[0].label == "Travel key" && passkeys[0].last_used_at.is_some())
    );

    let stale = authenticator.assertion(challenge(&service).await?, 2)?;
    let session = replacement(
        service
            .credentials(
                &login.token,
                change(CredentialOperation::RevokePasskey {
                    credential_id: registered.credential_id.clone(),
                }),
                "test".into(),
            )
            .await?,
    )?;
    ensure!(session.authentication == login.authentication);
    ensure!(service.refresh(&login.token, "test".into()).await.is_err());
    ensure!(
        service
            .begin_passkey_login(
                PasskeyLoginBeginRequest {
                    username: "root".into()
                },
                "test".into()
            )
            .await
            .is_err()
    );
    let registered = service
        .finish_passkey_registration(
            &session.token,
            authenticator.registration(
                begin(&service, &session.token).await?,
                "https://console.local",
            )?,
            "test".into(),
        )
        .await?;
    ensure!(registered.session.authentication == session.authentication);
    let error = service
        .finish_passkey_login(stale, "test".into())
        .await
        .err()
        .context("stale epoch")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    let session = replacement(
        service
            .credentials(
                &registered.session.token,
                change(CredentialOperation::DisablePassword {}),
                "test".into(),
            )
            .await?,
    )?;
    let error = service
        .credentials(
            &session.token,
            change(CredentialOperation::RevokePasskey {
                credential_id: registered.credential_id,
            }),
            "test".into(),
        )
        .await
        .err()
        .context("last primary credential")?;
    ensure!(error.code == ConsoleErrorCode::AdmissionRejected);
    Ok(())
}

#[tokio::test]
async fn passkey_login_requires_user_verification() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let (service, session) = fixture(boot.clone()).await?;
    let authenticator = Authenticator::new()?;
    service
        .finish_passkey_registration(
            &session.token,
            authenticator.registration(
                begin(&service, &session.token).await?,
                "https://console.local",
            )?,
            "test".into(),
        )
        .await?;
    let without_uv = authenticator.assertion_with_flags(challenge(&service).await?, 1, 0x01)?;
    let state = boot.kernel().state();
    let credential_path = root_credential_path(state).await?;
    let before_credentials = state.read(&credential_path).await?;
    let before_sessions = service.sessions().await?;
    ensure!(before_sessions.next.is_none());
    let error = service
        .finish_passkey_login(without_uv, "test".into())
        .await
        .err()
        .context("UP without UV cannot establish Passkey authentication")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(state.read(&credential_path).await? == before_credentials);
    let after_sessions = service.sessions().await?;
    ensure!(after_sessions.next.is_none());
    ensure!(after_sessions.entries.len() == before_sessions.entries.len());
    Ok(())
}

/// Pause one storage operation after the service has passed its entry checks.
struct GatedState {
    memory: Backend,
    pause_challenge_read: AtomicBool,
    pause_after_challenge_take: AtomicBool,
    pause_next_read: AtomicBool,
    pause_credential_write: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl GatedState {
    fn new() -> Self {
        Self {
            memory: InMemoryBackend::new().into_backend(),
            pause_challenge_read: AtomicBool::new(false),
            pause_after_challenge_take: AtomicBool::new(false),
            pause_next_read: AtomicBool::new(false),
            pause_credential_write: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        }
    }

    fn bootstrap(self: &Arc<Self>) -> Arc<Bootstrap> {
        Arc::new(Bootstrap::from_kernel(
            KernelBuilder::new(
                self.memory
                    .clone()
                    .with_read(self.clone())
                    .with_bounded_read(self.clone())
                    .with_write(self.clone())
                    .with_bounded_write(self.clone()),
            )
            .build(),
        ))
    }

    async fn pause(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

impl StateRead for GatedState {
    type Read<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateObservation>> + Send + 'a>>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            if self.pause_next_read.swap(false, Ordering::SeqCst)
                || (path.to_string() == "state://vault/console/challenges"
                    && self.pause_challenge_read.swap(false, Ordering::SeqCst))
            {
                self.pause().await;
            }
            self.memory.read_tainted(path).await
        })
    }
}

impl StateBoundedRead for GatedState {
    type BoundedRead<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateObservation>> + Send + 'a>>;

    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedRead<'a> {
        Box::pin(async move {
            if self.pause_next_read.swap(false, Ordering::SeqCst)
                || (path.to_string() == "state://vault/console/challenges"
                    && self.pause_challenge_read.swap(false, Ordering::SeqCst))
            {
                self.pause().await;
            }
            self.memory.read_tainted_bounded(path, limit).await
        })
    }
}

impl StateWrite for GatedState {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if path.to_string().starts_with(CREDENTIALS_PREFIX)
                && self.pause_credential_write.swap(false, Ordering::SeqCst)
            {
                self.pause().await;
            }
            let committed = self.memory.mutate(path, mutation).await?;
            if path.to_string() == "state://vault/console/challenges"
                && self
                    .pause_after_challenge_take
                    .swap(false, Ordering::SeqCst)
            {
                self.pause_next_read.store(true, Ordering::SeqCst);
            }
            Ok(committed)
        })
    }
}

impl StateBoundedWrite for GatedState {
    type BoundedWrite<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<StateValue>,
        value: TaintedValue,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(async move {
            if path.to_string().starts_with(CREDENTIALS_PREFIX)
                && self.pause_credential_write.swap(false, Ordering::SeqCst)
            {
                self.pause().await;
            }
            let committed = self
                .memory
                .write_cas_tainted_bounded(path, expected, value.value, value.taint, limit)
                .await?;
            if path.to_string() == "state://vault/console/challenges"
                && self
                    .pause_after_challenge_take
                    .swap(false, Ordering::SeqCst)
            {
                self.pause_next_read.store(true, Ordering::SeqCst);
            }
            Ok(committed)
        })
    }

    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<StateValue>,
        taint: xolotl_types::TaintSet,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(
            self.memory
                .write_compare_delete_tainted_bounded(path, expected, taint, limit),
        )
    }
}

async fn replace_session_evidence(
    store: &dyn xolotl_console::session_store::ConsoleSessionStore,
    sid: &str,
    authentication: &AuthenticationEvidence,
) -> anyhow::Result<()> {
    let original = store.get(sid).await?.context("session")?;
    let value: StateValue = serde_json::from_slice(&original.encode()?)?;
    let mut record = value.into_map().context("session record")?;
    record.insert(
        "authentication".into(),
        serde_json::from_value(serde_json::to_value(authentication)?)?,
    )?;
    let row = xolotl_console::session_store::ConsoleSession::decode(
        sid,
        &serde_json::to_vec(&StateValue::from(record))?,
    )?;
    store.compare_replace(original, row).await?;
    Ok(())
}

#[tokio::test]
async fn registration_rechecks_recent_window_and_complete_evidence_after_storage_wait()
-> anyhow::Result<()> {
    for expire_window in [true, false] {
        let gate = Arc::new(GatedState::new());
        let (service, session) = fixture(gate.bootstrap()).await?;
        let authenticator = Authenticator::new()?;
        let request = authenticator.registration(
            begin(&service, &session.token).await?,
            "https://console.local",
        )?;
        let deadline = system_now_millis() + 1_000;
        let verified_at = if expire_window {
            deadline - ConsoleAuthConfig::default().mfa.recent_auth_ttl_ms
        } else {
            session
                .authentication
                .authenticated_at()
                .context("passkey authentication time")?
        };
        let authentication = AuthenticationEvidence {
            primary: PrimaryAuthentication::Password { verified_at },
            secondary: None,
        };
        replace_session_evidence(service.store.as_ref(), &session.sid, &authentication).await?;
        let credential_path = root_credential_path(&gate.memory).await?;
        let before = gate.memory.read(&credential_path).await?;
        gate.pause_challenge_read.store(true, Ordering::SeqCst);
        let finish = service.finish_passkey_registration(&session.token, request, "test".into());
        tokio::pin!(finish);
        tokio::select! {
            result = &mut finish => anyhow::bail!("registration completed before storage wait: {result:?}"),
            entered = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()) => entered?,
        }
        if expire_window {
            while system_now_millis() <= deadline {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        } else {
            let key = pqc_key::PqcSigningKey::generate();
            let substituted = AuthenticationEvidence {
                primary: PrimaryAuthentication::PublicKey {
                    credential_key: key.descriptor(),
                    verified_at,
                },
                secondary: None,
            };
            ensure!(substituted.mfa_level() == authentication.mfa_level());
            ensure!(substituted.authenticated_at() == authentication.authenticated_at());
            replace_session_evidence(service.store.as_ref(), &session.sid, &substituted).await?;
        }
        gate.release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(5), finish)
            .await?
            .err()
            .context("registration must revalidate its authorizing evidence")?;
        ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
        ensure!(gate.memory.read(&credential_path).await? == before);
    }
    Ok(())
}

#[tokio::test]
async fn registration_cannot_commit_after_its_consumed_challenge_expires() -> anyhow::Result<()> {
    let gate = Arc::new(GatedState::new());
    let (service, session) = fixture(gate.bootstrap()).await?;
    let authenticator = Authenticator::new()?;
    let request = authenticator.registration(
        begin(&service, &session.token).await?,
        "https://console.local",
    )?;
    let ledger_path = Path::parse("state://vault/console/challenges")?;
    let raw = gate
        .memory
        .read(&ledger_path)
        .await?
        .context("challenge ledger")?;
    let mut ledger: Value = serde_json::from_str(raw.as_str().context("encoded ledger")?)?;
    let deadline = system_now_millis() + 1_000;
    ledger[&request.challenge_id]["expires_at"] = json!(deadline);
    ledger[&request.challenge_id]["payload"]["expires_at"] = json!(deadline);
    gate.memory
        .write_set(
            &ledger_path,
            StateValue::string(serde_json::to_string(&ledger)?),
        )
        .await?;
    let credential_path = root_credential_path(&gate.memory).await?;
    let before = gate.memory.read(&credential_path).await?;
    // Consumption and the first expiry check complete before this later read waits.
    gate.pause_after_challenge_take
        .store(true, Ordering::SeqCst);
    let finish = service.finish_passkey_registration(&session.token, request, "test".into());
    tokio::pin!(finish);
    tokio::select! {
        result = &mut finish => anyhow::bail!("registration completed before storage wait: {result:?}"),
        entered = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()) => entered?,
    }
    while system_now_millis() <= deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    gate.release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(5), finish)
        .await?
        .err()
        .context("registration must retain its original challenge deadline")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(gate.memory.read(&credential_path).await? == before);
    Ok(())
}

#[tokio::test]
async fn login_cannot_commit_after_its_consumed_challenge_expires() -> anyhow::Result<()> {
    let gate = Arc::new(GatedState::new());
    let (service, session) = fixture(gate.bootstrap()).await?;
    let authenticator = Authenticator::new()?;
    service
        .finish_passkey_registration(
            &session.token,
            authenticator.registration(
                begin(&service, &session.token).await?,
                "https://console.local",
            )?,
            "test".into(),
        )
        .await?;
    let request = authenticator.assertion(challenge(&service).await?, 1)?;
    let ledger_path = Path::parse("state://vault/console/challenges")?;
    let raw = gate
        .memory
        .read(&ledger_path)
        .await?
        .context("challenge ledger")?;
    let mut ledger: Value = serde_json::from_str(raw.as_str().context("encoded ledger")?)?;
    let deadline = system_now_millis() + 1_000;
    ledger[&request.challenge_id]["expires_at"] = json!(deadline);
    ledger[&request.challenge_id]["payload"]["expires_at"] = json!(deadline);
    gate.memory
        .write_set(
            &ledger_path,
            StateValue::string(serde_json::to_string(&ledger)?),
        )
        .await?;
    let credential_path = root_credential_path(&gate.memory).await?;
    let before = gate.memory.read(&credential_path).await?;
    let before_sessions = service.sessions().await?;
    ensure!(before_sessions.next.is_none());
    // The single-use challenge is consumed while valid; later account I/O waits.
    gate.pause_after_challenge_take
        .store(true, Ordering::SeqCst);
    let finish = service.finish_passkey_login(request, "test".into());
    tokio::pin!(finish);
    tokio::select! {
        result = &mut finish => anyhow::bail!("login completed before storage wait: {result:?}"),
        entered = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()) => entered?,
    }
    while system_now_millis() <= deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    gate.release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(5), finish)
        .await?
        .err()
        .context("login must retain its original challenge deadline")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(gate.memory.read(&credential_path).await? == before);
    let after_sessions = service.sessions().await?;
    ensure!(after_sessions.next.is_none());
    ensure!(after_sessions.entries.len() == before_sessions.entries.len());
    Ok(())
}

#[tokio::test]
async fn passkey_evidence_precedes_credential_commit_and_requires_its_cas() -> anyhow::Result<()> {
    let gate = Arc::new(GatedState::new());
    let (service, session) = fixture(gate.bootstrap()).await?;
    let authenticator = Authenticator::new()?;
    let registered = service
        .finish_passkey_registration(
            &session.token,
            authenticator.registration(
                begin(&service, &session.token).await?,
                "https://console.local",
            )?,
            "test".into(),
        )
        .await?;
    for conflict in [false, true] {
        let request =
            authenticator.assertion(challenge(&service).await?, if conflict { 2 } else { 1 })?;
        let before = service.sessions().await?;
        ensure!(before.next.is_none());
        gate.pause_credential_write.store(true, Ordering::SeqCst);
        let finish = service.finish_passkey_login(request, "test".into());
        tokio::pin!(finish);
        tokio::select! {
            result = &mut finish => anyhow::bail!("login completed before credential CAS: {result:?}"),
            entered = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()) => entered?,
        }
        let waiting_at = system_now_millis();
        if conflict {
            let renamed = service
                .credentials(
                    &registered.session.token,
                    change(CredentialOperation::RenamePasskey {
                        credential_id: registered.credential_id.clone(),
                        label: "Concurrent edit".into(),
                    }),
                    "test".into(),
                )
                .await?;
            ensure!(matches!(
                renamed,
                CredentialResponse::Updated {
                    sessions_invalidated: false,
                    session: None
                }
            ));
        } else {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let released_at = system_now_millis();
        gate.release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), finish).await?;
        if conflict {
            let error = result
                .err()
                .context("a losing credential CAS cannot issue a session")?;
            ensure!(error.code == ConsoleErrorCode::Conflict);
            let after = service.sessions().await?;
            ensure!(after.next.is_none() && after.entries.len() == before.entries.len());
        } else {
            let login = result?;
            let PrimaryAuthentication::PasskeyUv {
                credential_id,
                verified_at,
            } = login.authentication.primary
            else {
                anyhow::bail!("passkey UV evidence");
            };
            ensure!(credential_id == registered.credential_id);
            ensure!(verified_at <= waiting_at && verified_at < released_at);
            let status = service
                .credentials(
                    &login.token,
                    change(CredentialOperation::Status {}),
                    "test".into(),
                )
                .await?;
            ensure!(matches!(
                status,
                CredentialResponse::Current { passkeys, .. }
                if passkeys.iter().any(|passkey| passkey.credential_id == registered.credential_id
                    && passkey.last_used_at == Some(verified_at))
            ));
        }
    }
    Ok(())
}
