//! WebAuthn ceremonies bind account credentials, session and relying party.

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRegistrationRecord {
    credential_epoch: String,
    label: String,
    expires_at: i64,
    state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyAuthenticationRecord {
    credential_epoch: String,
    expires_at: i64,
    state: PasskeyAuthentication,
}

impl ConsoleAuth {
    fn webauthn(&self) -> Result<Webauthn, AuthError> {
        if !self.config.webauthn.enabled {
            return Err(AuthError::AccountUnavailable);
        }
        let origin = Url::parse(&self.config.webauthn.rp_origin)
            .map_err(|error| AuthError::Crypto(format!("invalid WebAuthn origin: {error}")))?;
        WebauthnBuilder::new(&self.config.webauthn.rp_id, &origin)
            .map_err(|error| AuthError::Crypto(error.to_string()))?
            .rp_name(&self.config.webauthn.rp_name)
            .timeout(Duration::from_millis(
                self.config.webauthn.challenge_ttl_ms as u64,
            ))
            .build()
            .map_err(|error| AuthError::Crypto(error.to_string()))
    }

    /// Begin passkey registration for the authenticated bearer principal.
    pub(crate) async fn begin_passkey_registration(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        req: PasskeyRegisterBeginRequest,
        source_addr: String,
    ) -> Result<PasskeyRegisterBeginResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let principal = self.authenticate_token(boot, bearer).await?;
        let state = boot.kernel().state();
        let authorized_epoch = self
            .recent_credential_management(state, bearer, &principal)
            .await?;
        let user = read_user(state, &principal.username)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }
        let webauthn = self.webauthn()?;
        credentials::validate_label(&req.label)?;
        if let Some(display_name) = &req.display_name {
            credentials::validate_label(display_name)?;
        }
        let record = credentials::read(state, &user.username, self.credential_sealer()?).await?;
        if record.epoch != authorized_epoch {
            return Err(AuthError::InvalidSession);
        }
        if record.passkeys.len() >= credentials::MAX_PASSKEYS {
            return Err(AuthError::InvalidCredentialRequest);
        }
        let exclude = record
            .passkeys
            .values()
            .map(|record| record.credential.cred_id().clone())
            .collect::<Vec<_>>();
        let display_name = req.display_name.as_deref().unwrap_or(&user.username);
        let (public_key, registration) = webauthn
            .start_passkey_registration(
                stable_user_uuid(&user.account_id),
                &user.username,
                display_name,
                Some(exclude),
            )
            .map_err(|error| AuthError::Crypto(error.to_string()))?;
        let expires_at = self
            .host_runtime
            .now_millis()
            .saturating_add(self.config.webauthn.challenge_ttl_ms);
        let challenge_id = challenges::issue(
            &self.host_runtime,
            state,
            &self.config.challenges,
            challenges::Binding::PasskeyRegistration {
                username: user.username.clone(),
                sid: bearer
                    .split_once('.')
                    .ok_or(AuthError::InvalidSession)?
                    .0
                    .into(),
            },
            &source_addr,
            expires_at,
            &PasskeyRegistrationRecord {
                credential_epoch: record.epoch,
                label: req.label,
                expires_at,
                state: registration,
            },
        )
        .await?;
        record_auth_audit(
            boot,
            "console_credential",
            Some(&user.username),
            Some(&source_addr),
            "passkey_register_begin",
            Some(&principal.authentication),
        )?;
        Ok(PasskeyRegisterBeginResponse {
            challenge_id,
            public_key,
        })
    }

    /// Finish passkey registration and persist the credential.
    pub(crate) async fn finish_passkey_registration(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        req: PasskeyRegisterFinishRequest,
        source_addr: String,
    ) -> Result<PasskeyRegisterFinishResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let principal = self.authenticate_token(boot, bearer).await?;
        let state = boot.kernel().state();
        let authorized_epoch = self
            .recent_credential_management(state, bearer, &principal)
            .await?;
        let sid = bearer.split_once('.').ok_or(AuthError::InvalidSession)?.0;
        let challenge: PasskeyRegistrationRecord = challenges::take(
            &self.host_runtime,
            state,
            &req.challenge_id,
            &challenges::Binding::PasskeyRegistration {
                username: principal.username.clone(),
                sid: sid.into(),
            },
        )
        .await?;
        let PasskeyRegistrationRecord {
            credential_epoch,
            label,
            expires_at,
            state: registration,
        } = challenge;
        if expires_at <= self.host_runtime.now_millis() || credential_epoch != authorized_epoch {
            return Err(AuthError::InvalidChallenge);
        }
        let username = &principal.username;
        let user = read_user(state, username)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        let mut record = credentials::read(state, username, self.credential_sealer()?).await?;
        if record.epoch != authorized_epoch {
            return Err(AuthError::InvalidSession);
        }
        let webauthn = self.webauthn()?;
        let credential = webauthn
            .finish_passkey_registration(&req.credential, &registration)
            .map_err(|_error| AuthError::InvalidCredentials)?;
        let credential_id = passkey_credential_id(&credential);
        if record.passkeys.contains_key(&credential_id)
            || record.passkeys.len() >= credentials::MAX_PASSKEYS
        {
            return Err(AuthError::InvalidCredentialRequest);
        }
        record.passkeys.insert(
            credential_id.clone(),
            credentials::StoredPasskey {
                credential,
                label,
                created_at: self.host_runtime.now_millis(),
                last_used_at: None,
            },
        );
        record.rotate_epoch()?;
        let current = self.authenticate_token(boot, bearer).await?;
        if current != principal
            || self
                .recent_credential_management(state, bearer, &current)
                .await?
                != authorized_epoch
        {
            return Err(AuthError::InvalidSession);
        }
        if expires_at <= self.host_runtime.now_millis() {
            return Err(AuthError::InvalidChallenge);
        }
        record_auth_audit(
            boot,
            "console_credential",
            Some(username),
            Some(&source_addr),
            "passkey_register_started",
            Some(&principal.authentication),
        )?;
        credentials::write(state, username, &record, self.credential_sealer()?).await?;
        record_auth_audit(
            boot,
            "console_credential",
            Some(username),
            Some(&source_addr),
            "passkey_register_finish",
            Some(&principal.authentication),
        )?;
        let account = self.local_snapshot(state, &user).await?;
        let session = self
            .issue_session(
                state,
                &account,
                source_addr,
                principal.authentication,
                record.epoch,
                principal.authority_ceiling,
            )
            .await?;
        Ok(PasskeyRegisterFinishResponse {
            credential_id,
            session,
        })
    }

    /// Begin passkey login for an active user.
    pub(crate) async fn begin_passkey_login(
        &self,
        boot: &Bootstrap,
        req: PasskeyLoginBeginRequest,
        source_addr: String,
    ) -> Result<PasskeyLoginBeginResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let state = boot.kernel().state();
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        self.mfa_limits(state, &username, &source_addr).await?;
        let user = read_user(state, &username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }
        let record = credentials::read(state, &username, self.credential_sealer()?).await?;
        if record.passkeys.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }
        let credentials = record
            .passkeys
            .values()
            .map(|record| record.credential.clone())
            .collect::<Vec<_>>();
        let webauthn = self.webauthn()?;
        let (public_key, authentication) = webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|error| AuthError::Crypto(error.to_string()))?;
        let expires_at = self
            .host_runtime
            .now_millis()
            .saturating_add(self.config.webauthn.challenge_ttl_ms);
        let challenge_id = challenges::issue(
            &self.host_runtime,
            state,
            &self.config.challenges,
            challenges::Binding::PasskeyAuthentication {
                username: user.username.clone(),
            },
            &source_addr,
            expires_at,
            &PasskeyAuthenticationRecord {
                credential_epoch: record.epoch,
                expires_at,
                state: authentication,
            },
        )
        .await?;
        record_auth_audit(
            boot,
            "console_credential",
            Some(&user.username),
            Some(&source_addr),
            "passkey_login_begin",
            None,
        )?;
        Ok(PasskeyLoginBeginResponse {
            challenge_id,
            public_key,
        })
    }

    /// Finish passkey login and issue an MFA-level session.
    pub(crate) async fn finish_passkey_login(
        &self,
        boot: &Bootstrap,
        req: PasskeyLoginFinishRequest,
        source_addr: String,
    ) -> Result<LoginResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        let result = self
            .finish_passkey_login_inner(boot.kernel().state(), req, source_addr.clone())
            .await;
        let result = match result {
            Err(error) => Err(self
                .mfa_failure(boot.kernel().state(), &username, &source_addr, error)
                .await),
            ok => ok,
        };
        match &result {
            Ok(response) => record_auth_audit(
                boot,
                "console_login",
                Some(&username),
                Some(&source_addr),
                "passkey_ok",
                Some(&response.authentication),
            )?,
            Err(err) => record_auth_audit(
                boot,
                "console_login_failed",
                Some(&username),
                Some(&source_addr),
                audit_outcome(err),
                None,
            )?,
        }
        result
    }

    async fn finish_passkey_login_inner(
        &self,
        state: &Backend,
        req: PasskeyLoginFinishRequest,
        source_addr: String,
    ) -> Result<LoginResponse, AuthError> {
        let username = req.username.trim().to_string();
        self.mfa_limits(state, &username, &source_addr).await?;
        let challenge: PasskeyAuthenticationRecord = challenges::take(
            &self.host_runtime,
            state,
            &req.challenge_id,
            &challenges::Binding::PasskeyAuthentication {
                username: username.clone(),
            },
        )
        .await?;
        let PasskeyAuthenticationRecord {
            credential_epoch,
            expires_at,
            state: authentication,
        } = challenge;
        if expires_at <= self.host_runtime.now_millis() {
            return Err(AuthError::InvalidChallenge);
        }
        let user = read_user(state, &username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }
        let mut record = credentials::read(state, &username, self.credential_sealer()?).await?;
        if record.epoch != credential_epoch {
            return Err(AuthError::InvalidChallenge);
        }
        let webauthn = self.webauthn()?;
        let auth_result = webauthn
            .finish_passkey_authentication(&req.credential, &authentication)
            .map_err(|_error| AuthError::InvalidCredentials)?;
        if !auth_result.user_verified() {
            return Err(AuthError::InvalidCredentials);
        }
        let verified_at = self.host_runtime.now_millis();
        let id = URL_SAFE_NO_PAD.encode(auth_result.cred_id().as_ref());
        let stored = record
            .passkeys
            .get_mut(&id)
            .ok_or(AuthError::InvalidCredentials)?;
        if stored.credential.update_credential(&auth_result).is_none() {
            return Err(AuthError::InvalidCredentials);
        }
        stored.last_used_at = Some(
            verified_at
                .max(stored.created_at)
                .max(stored.last_used_at.unwrap_or_default()),
        );
        if expires_at <= self.host_runtime.now_millis() {
            return Err(AuthError::InvalidChallenge);
        }
        credentials::write(state, &username, &record, self.credential_sealer()?).await?;
        self.clear_login_failures(&username, &source_addr, self.host_runtime.now_millis());
        clear_lockout(state, &username).await?;
        let account = self.local_snapshot(state, &user).await?;
        self.issue_session(
            state,
            &account,
            source_addr,
            AuthenticationEvidence {
                primary: PrimaryAuthentication::PasskeyUv {
                    credential_id: id,
                    verified_at,
                },
                secondary: None,
            },
            record.epoch,
            None,
        )
        .await
    }
}

pub(super) fn passkey_credential_id(credential: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(credential.cred_id().as_ref())
}

fn stable_user_uuid(username: &str) -> Uuid {
    let digest = Sha256::digest(username.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
