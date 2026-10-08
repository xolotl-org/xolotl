//! One vault aggregate serializes factor enrollment, replay counters and recovery
//! consumption. Its policy epoch invalidates sessions after credential changes.

mod enrollment;

use super::*;
use crate::SecondaryAuthentication;
use crate::mfa::{
    FactorAvailability, FactorSummary, MfaContext, MfaEnrollmentContext, MfaEnrollmentProgress,
    MfaEnrollmentStep, MfaInteractionInput, MfaOptions, MfaProof, MfaProvider,
    MfaProviderDescriptor, MfaProviderError, MfaProviderSummary, MfaProviderUsage, MfaPurpose,
    MfaRequest, MfaResponse, TotpProvider,
};
use enrollment::EnrollmentInvocation;
use serde_json::Value as JsonValue;
use std::sync::Arc;

use super::credentials::{
    AccountCredentials, EnrollmentPhase, EnrollmentWaiting, MAX_FACTORS, PendingEnrollment,
    RECOVERY_COUNT, StoredFactor, read_by_key, valid_provider_id, validate_label, write_by_key,
    write_reserving_enrollment_claim_by_key,
};
#[cfg(test)]
use super::credentials::{read, write};

const MAX_PROOF_BYTES: usize = 16 * 1024;
const MAX_PROVIDERS: usize = 32;
const MAX_JSON_DEPTH: usize = 32;

/// One validated declaration is fixed for the lifetime of this host. Discovery
/// and enrollment admission never ask an implementation to redeclare itself.
pub(super) struct InstalledProvider {
    pub(super) descriptor: MfaProviderDescriptor,
    pub(super) usage: MfaProviderUsage,
    pub(super) implementation: Arc<dyn MfaProvider>,
}

/// Concrete provider dispatch paths with independently declared input contracts.
#[derive(Clone, Copy)]
pub(super) enum ProviderOperation {
    Enrollment,
    Proof,
    Interaction,
}

pub(super) fn providers(
    config: &ConsoleAuthConfig,
) -> Result<BTreeMap<String, InstalledProvider>, AuthError> {
    if config.mfa.issuer.trim().is_empty()
        || config.mfa.issuer.len() > 128
        || config.mfa.install_totp && !config.mfa.totp.valid()
        || config.mfa.providers.len() > MAX_PROVIDERS - usize::from(config.mfa.install_totp)
        || config
            .mfa
            .provider_usage
            .keys()
            .any(|id| !valid_provider_id(id))
    {
        return Err(AuthError::Crypto(
            "invalid MFA provider configuration".into(),
        ));
    }
    let mut providers = BTreeMap::new();
    if config.mfa.install_totp {
        install_provider(
            &mut providers,
            Arc::new(TotpProvider(config.mfa.totp.clone())),
            &config.mfa.provider_usage,
        )?;
    }
    for provider in &config.mfa.providers {
        install_provider(&mut providers, provider.clone(), &config.mfa.provider_usage)?;
    }
    Ok(providers)
}

fn install_provider(
    providers: &mut BTreeMap<String, InstalledProvider>,
    implementation: Arc<dyn MfaProvider>,
    usage: &BTreeMap<String, MfaProviderUsage>,
) -> Result<(), AuthError> {
    let descriptor = implementation.descriptor();
    if !valid_provider_id(&descriptor.provider_id)
        || validate_label(&descriptor.label).is_err()
        || providers.contains_key(&descriptor.provider_id)
        || descriptor.enrollment.as_ref().is_some_and(|enrollment| {
            !valid_schema(&enrollment.setup_schema)
                || enrollment
                    .begin_schema
                    .as_ref()
                    .is_some_and(|schema| !valid_schema(schema))
                || enrollment
                    .pending_schema
                    .as_ref()
                    .is_some_and(|schema| !valid_schema(schema))
        })
        || descriptor
            .authentication
            .proof_schema
            .as_ref()
            .is_some_and(|schema| !valid_schema(schema))
        || descriptor
            .authentication
            .interaction
            .as_ref()
            .is_some_and(|interaction| !valid_schema(&interaction.challenge_schema))
        || (descriptor.authentication.proof_schema.is_none()
            && descriptor.authentication.interaction.is_none())
        || !encoded_fits(&descriptor)
    {
        return Err(AuthError::Crypto(
            "invalid or duplicate MFA provider".into(),
        ));
    }
    providers.insert(
        descriptor.provider_id.clone(),
        InstalledProvider {
            usage: usage
                .get(&descriptor.provider_id)
                .copied()
                .unwrap_or_default(),
            descriptor,
            implementation,
        },
    );
    Ok(())
}

// Each node consumes at least one encoded byte. Checking this budget before
// serialization bounds traversal even for an extremely wide native JSON value.
// Recursive calls stop at the fixed container depth; no work stack is allocated.
pub(super) fn bounded_json(value: &JsonValue) -> bool {
    fn shape(value: &JsonValue, depth: usize, nodes: &mut usize) -> bool {
        let Some(remaining) = nodes.checked_sub(1) else {
            return false;
        };
        *nodes = remaining;
        match value {
            JsonValue::Object(fields) => {
                depth < MAX_JSON_DEPTH
                    && fields.iter().all(|(key, value)| {
                        key.len() <= MAX_PROOF_BYTES && shape(value, depth + 1, nodes)
                    })
            }
            JsonValue::Array(items) => {
                depth < MAX_JSON_DEPTH && items.iter().all(|value| shape(value, depth + 1, nodes))
            }
            JsonValue::String(text) => text.len() <= MAX_PROOF_BYTES,
            _ => true,
        }
    }
    let mut nodes = MAX_PROOF_BYTES;
    shape(value, 0, &mut nodes) && encoded_fits(value)
}

pub(super) fn valid_schema(schema: &JsonValue) -> bool {
    (schema.is_object() || schema.is_boolean()) && bounded_json(schema)
}

fn encoded_fits(value: &impl Serialize) -> bool {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("MFA JSON exceeds the encoded byte limit"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(MAX_PROOF_BYTES), value).is_ok()
}

/// Freeze the public HTTP representation once, using borrowed declarations so
/// assembly does not make a second owned copy of every provider schema.
#[cfg(feature = "http")]
pub(super) fn provider_catalog_json(
    providers: &BTreeMap<String, InstalledProvider>,
) -> Result<Arc<[u8]>, AuthError> {
    #[derive(Serialize)]
    struct Summary<'a> {
        descriptor: &'a MfaProviderDescriptor,
        usage: MfaProviderUsage,
    }

    let summaries: Vec<_> = providers
        .values()
        .map(|provider| Summary {
            descriptor: &provider.descriptor,
            usage: provider.usage,
        })
        .collect();
    serde_json::to_vec(&summaries)
        .map(Arc::from)
        .map_err(|_error| AuthError::Crypto("cannot encode MFA provider catalog".into()))
}

pub(super) fn provider_error(error: MfaProviderError) -> AuthError {
    match error {
        MfaProviderError::InvalidInput => AuthError::InvalidMfaRequest,
        MfaProviderError::InvalidProof => AuthError::InvalidCredentials,
        MfaProviderError::Unavailable => AuthError::State("MFA provider unavailable".into()),
        MfaProviderError::InvalidState => AuthError::State("invalid MFA verifier".into()),
    }
}

impl ConsoleAuth {
    #[cfg(feature = "http")]
    pub(crate) fn mfa_provider_json(&self) -> &Arc<[u8]> {
        &self.mfa_provider_json
    }

    pub(crate) fn mfa_providers(&self) -> Vec<MfaProviderSummary> {
        self.mfa_providers
            .values()
            .map(|provider| MfaProviderSummary {
                descriptor: provider.descriptor.clone(),
                usage: provider.usage,
            })
            .collect()
    }

    pub(super) fn provider_for(
        &self,
        provider_id: &str,
        operation: ProviderOperation,
    ) -> Result<&InstalledProvider, AuthError> {
        let provider = self
            .mfa_providers
            .get(provider_id)
            .ok_or(AuthError::MfaOperationUnavailable)?;
        let allowed = match operation {
            ProviderOperation::Enrollment => provider.usage.allow_enrollment,
            ProviderOperation::Proof | ProviderOperation::Interaction => {
                provider.usage.allow_authentication
            }
        };
        if !allowed {
            return Err(AuthError::MfaUsageDenied);
        }
        let supported = match operation {
            ProviderOperation::Enrollment => provider.descriptor.enrollment.is_some(),
            ProviderOperation::Proof => provider.descriptor.authentication.proof_schema.is_some(),
            ProviderOperation::Interaction => {
                provider.descriptor.authentication.interaction.is_some()
            }
        };
        if !supported {
            return Err(AuthError::MfaOperationUnavailable);
        }
        Ok(provider)
    }

    fn factor_summary(&self, factor_id: &str, factor: &StoredFactor) -> FactorSummary {
        FactorSummary {
            factor_id: factor_id.into(),
            provider_id: factor.provider_id.clone(),
            label: factor.label.clone(),
            created_at: factor.created_at,
            last_used_at: factor.last_used_at,
            availability: match self.mfa_providers.get(&factor.provider_id) {
                None => FactorAvailability::ProviderNotInstalled,
                Some(provider) if !provider.usage.allow_authentication => {
                    FactorAvailability::AuthenticationDisabled
                }
                Some(_) => FactorAvailability::Available,
            },
        }
    }

    pub(super) fn factor_summaries(&self, record: &AccountCredentials) -> Vec<FactorSummary> {
        record
            .factors
            .iter()
            .map(|(id, factor)| self.factor_summary(id, factor))
            .collect()
    }

    pub(super) fn required_error(&self, record: &AccountCredentials) -> AuthError {
        AuthError::MfaRequired {
            options: Some(MfaOptions {
                factors: self.factor_summaries(record),
                recovery_code_available: !record.recovery.is_empty(),
            }),
        }
    }

    pub(super) fn mfa_context<'a>(
        &'a self,
        username: &'a str,
        account: &'a AccountKey,
        factor_id: &'a str,
        label: &'a str,
        purpose: MfaPurpose,
    ) -> MfaContext<'a> {
        MfaContext {
            username,
            authority_id: account.authority_id(),
            account_id: account.instance_id(),
            factor_id,
            label,
            purpose,
            issuer: &self.config.mfa.issuer,
            now_ms: self.host_runtime.now_millis(),
        }
    }

    pub(super) async fn mfa_limits(
        &self,
        state: &Backend,
        username: &str,
        source: &str,
    ) -> Result<(), AuthError> {
        let now = self.host_runtime.now_millis();
        self.check_rate_limits(username, source, now)?;
        let lockout = read_lockout(state, username).await?;
        if lockout.is_locked(now) {
            return Err(AuthError::RateLimited {
                retry_after_ms: lockout.remaining_ms(now),
            });
        }
        Ok(())
    }

    pub(super) async fn mfa_limits_for_account(
        &self,
        state: &Backend,
        key: &AccountKey,
        source: &str,
    ) -> Result<(), AuthError> {
        let now = self.host_runtime.now_millis();
        self.check_rate_limits(
            &format!("{}:{}", key.authority_id(), key.instance_id()),
            source,
            now,
        )?;
        let lockout = read_account_lockout(state, key).await?;
        if lockout.is_locked(now) {
            return Err(AuthError::RateLimited {
                retry_after_ms: lockout.remaining_ms(now),
            });
        }
        Ok(())
    }

    pub(super) fn clear_login_failures_for_account(
        &self,
        key: &AccountKey,
        source: &str,
        now: i64,
    ) {
        self.clear_login_failures(
            &format!("{}:{}", key.authority_id(), key.instance_id()),
            source,
            now,
        );
    }

    pub(super) async fn mfa_failure_for_account(
        &self,
        state: &Backend,
        key: &AccountKey,
        source: &str,
        error: AuthError,
    ) -> AuthError {
        if matches!(
            error,
            AuthError::InvalidCredentials | AuthError::InvalidMfaRequest
        ) {
            let now = self.host_runtime.now_millis();
            self.record_login_failure(
                &format!("{}:{}", key.authority_id(), key.instance_id()),
                source,
                now,
            );
            if let Err(error) = record_factor_lockout_failure(state, key, now).await {
                return error;
            }
        }
        error
    }

    pub(super) async fn mfa_failure(
        &self,
        state: &Backend,
        username: &str,
        source: &str,
        error: AuthError,
    ) -> AuthError {
        if matches!(
            error,
            AuthError::InvalidCredentials | AuthError::InvalidMfaRequest
        ) {
            let now = self.host_runtime.now_millis();
            self.record_login_failure(username, source, now);
            if let Err(error) = record_account_lockout_failure(state, username, now).await {
                return error;
            }
        }
        error
    }

    pub(super) async fn verify_record(
        &self,
        username: &str,
        record: &mut AccountCredentials,
        proof: &MfaProof,
        purpose: MfaPurpose,
    ) -> Result<SecondaryAuthentication, AuthError> {
        if let MfaProof::RecoveryCode { code } = proof {
            if code.len() > MAX_PROOF_BYTES {
                return Err(AuthError::InvalidCredentials);
            }
            let hash = token_hash(code);
            let position = record
                .recovery
                .iter()
                .position(|value| value.as_bytes().ct_eq(hash.as_bytes()).unwrap_u8() == 1)
                .ok_or(AuthError::InvalidCredentials)?;
            record.recovery.remove(position);
            return Ok(SecondaryAuthentication::RecoveryCode {
                verified_at: self.host_runtime.now_millis(),
            });
        }
        let MfaProof::Factor {
            factor_id,
            response,
        } = proof
        else {
            return Err(AuthError::InvalidCredentials);
        };
        let factor = record
            .factors
            .get_mut(factor_id)
            .ok_or(AuthError::InvalidCredentials)?;
        let account = AccountKey::from_parts(&record.authority_id, &record.account_id);
        let next = self
            .verify_factor_proof(
                self.mfa_context(username, &account, factor_id, &factor.label, purpose),
                &factor.provider_id,
                &factor.verifier,
                response,
            )
            .await?;
        let verified_at = self.host_runtime.now_millis();
        factor.verifier = next;
        if purpose != MfaPurpose::Enrollment {
            factor.last_used_at = Some(
                verified_at
                    .max(factor.created_at)
                    .max(factor.last_used_at.unwrap_or_default()),
            );
        }
        Ok(SecondaryAuthentication::Factor {
            factor_id: factor_id.clone(),
            provider_id: factor.provider_id.clone(),
            verified_at,
        })
    }

    async fn verify_factor_proof(
        &self,
        context: MfaContext<'_>,
        provider_id: &str,
        verifier: &JsonValue,
        response: &JsonValue,
    ) -> Result<JsonValue, AuthError> {
        let provider = self.provider_for(provider_id, ProviderOperation::Proof)?;
        if !bounded_json(response) {
            return Err(AuthError::InvalidCredentials);
        }
        let deadline = crate::host_time::after(&self.host_runtime, Duration::from_secs(10))
            .map_err(|_error| AuthError::State("MFA provider timed out".into()))?;
        let next = crate::host_time::timeout_at(
            &self.host_runtime,
            deadline,
            provider
                .implementation
                .verify_proof(context, verifier, response),
        )
        .await
        .map_err(|_error| AuthError::State("MFA provider timed out".into()))?
        .map_err(provider_error)?;
        if !bounded_json(&next) {
            return Err(AuthError::State("invalid MFA verifier".into()));
        }
        Ok(next)
    }

    pub(super) async fn recent_credential_management(
        &self,
        state: &Backend,
        bearer: &str,
        principal: &ConsolePrincipal,
    ) -> Result<String, AuthError> {
        let sid = bearer.split_once('.').ok_or(AuthError::InvalidSession)?.0;
        let session = read_session(self.session_store.as_ref(), &session_path(sid)?)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        let record =
            read_by_key(state, &principal.account_key(), self.credential_sealer()?).await?;
        if session.credential_epoch != record.epoch
            || session.account_key() != principal.account_key()
            || AccountKey::from_parts(&record.authority_id, &record.account_id)
                != principal.account_key()
            || session.authentication != principal.authentication
        {
            return Err(AuthError::InvalidSession);
        }
        // Directory reads can consume the remaining recent-auth window. Make
        // the time decision only after all evidence and epoch reads complete.
        let now = self.host_runtime.now_millis();
        let authenticated_at = session
            .authentication
            .authenticated_at()
            .ok_or(AuthError::ReauthenticationRequired)?;
        if authenticated_at > now
            || now.saturating_sub(authenticated_at)
                > self.config.mfa.recent_auth_ttl_ms.clamp(30_000, 900_000)
        {
            return Err(AuthError::ReauthenticationRequired);
        }
        if !record.factors.is_empty() && principal.authentication.mfa_level() < 2 {
            return Err(self.required_error(&record));
        }
        Ok(record.epoch)
    }

    // Provider work can outlive the bearer or its recent-authentication window.
    // Recheck the original account/session binding before the credential CAS;
    // the CAS still arbitrates concurrent changes to the credential aggregate.
    async fn revalidate_mfa_management(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        principal: &ConsolePrincipal,
        record: &AccountCredentials,
    ) -> Result<AccountSnapshot, AuthError> {
        let state = boot.kernel().state();
        let account = self
            .current_account(state, &principal.account_key(), Some(&principal.username))
            .await?;
        if account.key != AccountKey::from_parts(&record.authority_id, &record.account_id) {
            return Err(AuthError::InvalidSession);
        }
        let current = self.authenticate_token(boot, bearer).await?;
        let current_epoch = self
            .recent_credential_management(state, bearer, &current)
            .await?;
        if current != *principal || current_epoch != record.epoch {
            return Err(AuthError::InvalidSession);
        }
        Ok(account)
    }

    pub(crate) async fn manage_mfa(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        request: MfaRequest,
        source: String,
    ) -> Result<MfaResponse, AuthError> {
        let event = match &request {
            MfaRequest::Status {} => "mfa_status",
            MfaRequest::Current {} => "mfa_enrollment_current",
            MfaRequest::Begin { .. } => "mfa_enrollment_begin",
            MfaRequest::Continue { .. } => "mfa_enrollment_continue",
            MfaRequest::Cancel { .. } => "mfa_enrollment_cancel",
            MfaRequest::Rename { .. } => "mfa_rename",
            MfaRequest::Remove { .. } => "mfa_remove",
            MfaRequest::RegenerateRecoveryCodes {} => "mfa_recovery_regenerate",
        };
        let result = self
            .manage_mfa_inner(boot, bearer, request, source.clone())
            .await;
        let (username, authentication, outcome) = match &result {
            Ok((_, username, authentication)) => {
                (Some(username.as_str()), Some(authentication), event)
            }
            Err(error) => (None, None, audit_outcome(error)),
        };
        record_auth_audit(
            boot,
            "console_credential",
            username,
            Some(&source),
            outcome,
            authentication,
        )?;
        result.map(|(response, _, _)| response)
    }

    async fn manage_mfa_inner(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        request: MfaRequest,
        source: String,
    ) -> Result<(MfaResponse, String, AuthenticationEvidence), AuthError> {
        let state = boot.kernel().state();
        let principal = self.authenticate_token(boot, bearer).await?;
        let account_key = principal.account_key();
        let mut record = read_by_key(state, &account_key, self.credential_sealer()?).await?;
        if matches!(request, MfaRequest::Status {}) {
            return Ok((
                MfaResponse::Status {
                    providers: self.mfa_providers(),
                    factors: self.factor_summaries(&record),
                    max_factors: MAX_FACTORS,
                    recovery_codes_remaining: record.recovery.len(),
                },
                principal.username,
                principal.authentication,
            ));
        }
        let authorized_epoch = self
            .recent_credential_management(state, bearer, &principal)
            .await?;
        if record.epoch != authorized_epoch {
            return Err(AuthError::InvalidSession);
        }
        self.mfa_limits_for_account(state, &account_key, &source)
            .await?;
        let sid = bearer.split_once('.').ok_or(AuthError::InvalidSession)?.0;
        if !matches!(
            request,
            MfaRequest::Current {} | MfaRequest::Continue { .. } | MfaRequest::Cancel { .. }
        ) && record.pending.as_ref().is_some_and(|pending| {
            matches!(pending.phase, EnrollmentPhase::InFlight { .. })
                && pending.expires_at > self.host_runtime.now_millis()
        }) {
            return Err(AuthError::CredentialConflict);
        }
        let mut recovery_codes = None;
        match request {
            MfaRequest::Current {} => {
                let response = self.current_factor_enrollment(&record, sid);
                return Ok((response, principal.username, principal.authentication));
            }
            MfaRequest::Begin {
                provider_id,
                label,
                replace_factor_id,
                input,
            } => {
                let response = self
                    .begin_factor_enrollment(
                        EnrollmentInvocation {
                            boot,
                            bearer,
                            principal: &principal,
                            record,
                            sid,
                        },
                        provider_id,
                        label,
                        replace_factor_id,
                        input,
                    )
                    .await?;
                return Ok((response, principal.username, principal.authentication));
            }
            MfaRequest::Continue {
                challenge_id,
                input,
            } => {
                let response = self
                    .continue_factor_enrollment(
                        EnrollmentInvocation {
                            boot,
                            bearer,
                            principal: &principal,
                            record,
                            sid,
                        },
                        challenge_id,
                        input,
                        source,
                    )
                    .await?;
                return Ok((response, principal.username, principal.authentication));
            }
            MfaRequest::Cancel { challenge_id } => {
                let response = self
                    .cancel_factor_enrollment(boot, bearer, &principal, record, sid, &challenge_id)
                    .await?;
                return Ok((response, principal.username, principal.authentication));
            }
            MfaRequest::Rename { factor_id, label } => {
                validate_label(&label).map_err(|_error| AuthError::InvalidMfaRequest)?;
                let factor = record
                    .factors
                    .get_mut(&factor_id)
                    .ok_or(AuthError::InvalidMfaRequest)?;
                factor.label = label;
                let factor = self.factor_summary(&factor_id, factor);
                self.revalidate_mfa_management(boot, bearer, &principal, &record)
                    .await?;
                write_by_key(state, &account_key, &record, self.credential_sealer()?).await?;
                return Ok((
                    MfaResponse::Renamed { factor },
                    principal.username,
                    principal.authentication,
                ));
            }
            MfaRequest::Remove { factor_id } => {
                if record.factors.remove(&factor_id).is_none() {
                    return Err(AuthError::InvalidMfaRequest);
                }
                record.pending = None;
                if record.factors.is_empty() {
                    record.recovery.clear();
                }
            }
            MfaRequest::RegenerateRecoveryCodes {} => {
                if record.factors.is_empty() {
                    return Err(self.required_error(&record));
                }
                record.pending = None;
                recovery_codes = Some(new_recovery_codes(&mut record)?);
            }
            MfaRequest::Status {} => return Err(AuthError::InvalidMfaRequest),
        }
        let account = self
            .revalidate_mfa_management(boot, bearer, &principal, &record)
            .await?;
        record.rotate_epoch()?;
        write_by_key(state, &account_key, &record, self.credential_sealer()?).await?;
        // Enrolling a new factor proves it is usable, not that an existing
        // credential was authenticated. Management preserves the complete
        // verification history, including after removing its last factor.
        let session = self
            .issue_session(
                state,
                &account,
                source,
                principal.authentication.clone(),
                record.epoch,
                principal.authority_ceiling.clone(),
            )
            .await?;
        Ok((
            MfaResponse::Updated {
                session,
                recovery_codes,
            },
            principal.username,
            principal.authentication,
        ))
    }
}

async fn release_enrollment_claim(
    state: &Backend,
    key: &AccountKey,
    claimed: &AccountCredentials,
    sealer: &CredentialSealer,
) -> Result<(), AuthError> {
    let mut current = read_by_key(state, key, sealer).await?;
    if current.authority_id != claimed.authority_id
        || current.account_id != claimed.account_id
        || current.epoch != claimed.epoch
        || current.pending.as_ref() != claimed.pending.as_ref()
    {
        return Err(AuthError::CredentialConflict);
    }
    current
        .pending
        .as_mut()
        .ok_or(AuthError::InvalidChallenge)?
        .phase = EnrollmentPhase::Ready {};
    write_by_key(state, key, &current, sealer).await
}

fn new_recovery_codes(record: &mut AccountCredentials) -> Result<Vec<String>, AuthError> {
    let codes: Vec<_> = (0..RECOVERY_COUNT)
        .map(|_| random_token(32))
        .collect::<Result<_, _>>()?;
    record.recovery = codes.iter().map(|code| token_hash(code)).collect();
    Ok(codes)
}

#[cfg(test)]
mod tests;
