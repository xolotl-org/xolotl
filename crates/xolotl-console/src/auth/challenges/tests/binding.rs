//! Ownership mismatches must not burn another caller's authentication challenge.

use super::*;
use crate::auth::test_key::TestSigningKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

// Use the same minimal ES256 authenticator as the public-service regression,
// so a retained challenge must still complete real WebAuthn verification.
struct Authenticator {
    key: PKey<Private>,
    id: Vec<u8>,
    cose: Vec<u8>,
}

async fn ledger(boot: &Bootstrap) -> anyhow::Result<Option<Value>> {
    Ok(boot.kernel().state().read(&Path::parse(LEDGER)?).await?)
}

async fn webauthn_fixture() -> anyhow::Result<(Arc<Bootstrap>, ConsoleAuth, String, String)> {
    let (base, _, token, password) = crate::service::tests::fixture().await?;
    let mut auth = ConsoleAuth::new(ConsoleAuthConfig {
        webauthn: ConsoleWebAuthnConfig {
            enabled: true,
            rp_id: "console.local".into(),
            rp_origin: "https://console.local".into(),
            ..Default::default()
        },
        ..Default::default()
    })?;
    auth.session_store = base.auth.session_store.clone();
    Ok((base.boot.clone(), auth, token, password))
}

async fn begin_registration(
    auth: &ConsoleAuth,
    boot: &Bootstrap,
    bearer: &str,
) -> anyhow::Result<PasskeyRegisterBeginResponse> {
    Ok(auth
        .begin_passkey_registration(
            boot,
            bearer,
            PasskeyRegisterBeginRequest {
                label: "Binding test authenticator".into(),
                display_name: None,
            },
            "registration-source".into(),
        )
        .await?)
}

fn key_request(challenge: &KeyChallengeResponse, signing_key: &TestSigningKey) -> KeyLoginRequest {
    KeyLoginRequest {
        username: "root".into(),
        challenge_id: challenge.challenge_id.clone(),
        signature: URL_SAFE_NO_PAD.encode(signing_key.sign(challenge.transcript.as_bytes())),
        origin: challenge.origin.clone(),
        key: signing_key.descriptor(),
        second_factor: None,
    }
}

#[tokio::test]
async fn key_finish_binds_username_and_origin_but_not_source() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let signing_key = TestSigningKey::generate();
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            pubkeys: vec![signing_key.descriptor()],
            ..Default::default()
        },
    )
    .await?;
    let auth = ConsoleAuth::new(ConsoleAuthConfig::default())?;
    let begin = || KeyChallengeRequest {
        username: "root".into(),
        origin: "https://console.local".into(),
    };
    let challenge = auth
        .begin_key_login(&boot, begin(), "original-source".into())
        .await?;
    let before = ledger(&boot).await?;
    let mut wrong_username = key_request(&challenge, &signing_key);
    wrong_username.username = "another-account".into();
    ensure!(matches!(
        auth.finish_key_login(&boot, wrong_username, "other-source".into())
            .await,
        Err(AuthError::InvalidChallenge)
    ));
    ensure!(ledger(&boot).await? == before);
    let mut wrong_origin = key_request(&challenge, &signing_key);
    wrong_origin.origin = "https://different.local".into();
    ensure!(matches!(
        auth.finish_key_login(&boot, wrong_origin, "other-source".into())
            .await,
        Err(AuthError::InvalidChallenge)
    ));
    ensure!(ledger(&boot).await? == before);
    let login = auth
        .finish_key_login(
            &boot,
            key_request(&challenge, &signing_key),
            "changed-source".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(auth.authenticate_token(&boot, &login.token).await?.username == "root");
    ensure!(matches!(
        auth.finish_key_login(
            &boot,
            key_request(&challenge, &signing_key),
            "changed-source".into()
        )
        .await,
        Err(AuthError::InvalidChallenge)
    ));

    let challenge = auth
        .begin_key_login(&boot, begin(), "original-source".into())
        .await?;
    let mut invalid = key_request(&challenge, &signing_key);
    invalid.signature = "invalid".into();
    ensure!(matches!(
        auth.finish_key_login(&boot, invalid, "changed-source".into())
            .await,
        Err(AuthError::InvalidCredentials)
    ));
    ensure!(matches!(
        auth.finish_key_login(
            &boot,
            key_request(&challenge, &signing_key),
            "changed-source".into()
        )
        .await,
        Err(AuthError::InvalidChallenge)
    ));
    Ok(())
}

#[tokio::test]
async fn passkey_registration_binds_original_sid_without_consuming_on_mismatch()
-> anyhow::Result<()> {
    let (boot, auth, token, password) = webauthn_fixture().await?;
    let other = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "same-account-other-session".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(token.split_once('.').context("original bearer")?.0 != other.sid);
    let authenticator = Authenticator::new()?;
    let request = authenticator.registration(
        begin_registration(&auth, &boot, &token).await?,
        "https://console.local",
    )?;
    let encoded = serde_json::to_vec(&request)?;
    let before = ledger(&boot).await?;
    ensure!(matches!(
        auth.finish_passkey_registration(&boot, &other.token, request, "other-source".into())
            .await,
        Err(AuthError::InvalidChallenge)
    ));
    ensure!(ledger(&boot).await? == before);
    // Rotation changes the bearer secret, not the session that owns registration.
    let refreshed = auth
        .refresh_session(&boot, &token, Some("refreshed-source"))
        .await?;
    ensure!(refreshed.sid == token.split_once('.').context("original bearer")?.0);
    let registered = auth
        .finish_passkey_registration(
            &boot,
            &refreshed.token,
            serde_json::from_slice(&encoded)?,
            "changed-source".into(),
        )
        .await?;
    ensure!(!registered.credential_id.is_empty());

    // Matching SID owns the attempt even when WebAuthn rejects its origin.
    let request = Authenticator::new()?.registration(
        begin_registration(&auth, &boot, &registered.session.token).await?,
        "https://different.local",
    )?;
    let encoded = serde_json::to_vec(&request)?;
    ensure!(matches!(
        auth.finish_passkey_registration(
            &boot,
            &registered.session.token,
            request,
            "changed-source".into()
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    ensure!(matches!(
        auth.finish_passkey_registration(
            &boot,
            &registered.session.token,
            serde_json::from_slice(&encoded)?,
            "changed-source".into()
        )
        .await,
        Err(AuthError::InvalidChallenge)
    ));
    Ok(())
}

#[tokio::test]
async fn passkey_login_binds_username_and_consumes_only_the_matching_attempt() -> anyhow::Result<()>
{
    let (boot, auth, token, _) = webauthn_fixture().await?;
    let authenticator = Authenticator::new()?;
    auth.finish_passkey_registration(
        &boot,
        &token,
        authenticator.registration(
            begin_registration(&auth, &boot, &token).await?,
            "https://console.local",
        )?,
        "test".into(),
    )
    .await?;
    let begin = || PasskeyLoginBeginRequest {
        username: "root".into(),
    };
    let challenge = auth
        .begin_passkey_login(&boot, begin(), "original-source".into())
        .await?;
    let mut request = authenticator.assertion(challenge, 1)?;
    let encoded = serde_json::to_vec(&request)?;
    let before = ledger(&boot).await?;
    request.username = "another-account".into();
    ensure!(matches!(
        auth.finish_passkey_login(&boot, request, "other-source".into())
            .await,
        Err(AuthError::InvalidChallenge)
    ));
    ensure!(ledger(&boot).await? == before);
    let login = auth
        .finish_passkey_login(
            &boot,
            serde_json::from_slice(&encoded)?,
            "changed-source".into(),
        )
        .await?;
    ensure!(login.authentication.mfa_level() == 2);
    ensure!(matches!(
        auth.finish_passkey_login(
            &boot,
            serde_json::from_slice(&encoded)?,
            "changed-source".into()
        )
        .await,
        Err(AuthError::InvalidChallenge)
    ));

    let challenge = auth
        .begin_passkey_login(&boot, begin(), "original-source".into())
        .await?;
    let request = authenticator.assertion(challenge, 2)?;
    let mut invalid = serde_json::to_value(&request)?;
    invalid["credential"]["response"]["signature"] = json!("AA");
    ensure!(matches!(
        auth.finish_passkey_login(
            &boot,
            serde_json::from_value(invalid)?,
            "changed-source".into()
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    // Bypass only local backoff to observe the consumed challenge directly.
    *auth.rate() = RateState::default();
    ensure!(matches!(
        auth.finish_passkey_login(&boot, request, "changed-source".into())
            .await,
        Err(AuthError::InvalidChallenge)
    ));
    Ok(())
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

    fn client_data(options: &JsonValue, ceremony: &str, origin: &str) -> anyhow::Result<Vec<u8>> {
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
        challenge: PasskeyLoginBeginResponse,
        counter: u32,
    ) -> anyhow::Result<PasskeyLoginFinishRequest> {
        let client_data = Self::client_data(
            &serde_json::to_value(challenge.public_key)?,
            "webauthn.get",
            "https://console.local",
        )?;
        let auth_data = Self::auth_data(0x05, counter); // UP and UV.
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
