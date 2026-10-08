//! Console owns verified identity, bounded interaction and the final credential CAS.
//! Providers never receive a session issuer or a credential-store write handle.

use super::*;
use crate::mfa::{
    MfaInteractionContext, MfaInteractionInput, MfaInteractionStep, MfaOptions, MfaProof,
    MfaPurpose,
};
use crate::{
    AuthenticationContinuation, AuthenticationInput, AuthenticationStep,
    CancelAuthenticationRequest, ContinueAuthenticationRequest, SecondaryAuthentication,
};
use credentials::AccountCredentials;
use serde_json::Value as JsonValue;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum AuthenticationPurpose {
    Login,
    StepUp { sid: String },
}

pub(super) struct AuthenticationStart<'a> {
    pub account: &'a AccountSnapshot,
    pub credentials: AccountCredentials,
    pub primary: PrimaryAuthentication,
    pub purpose: AuthenticationPurpose,
    pub proof: Option<&'a MfaProof>,
    pub bearer: Option<&'a str>,
    pub source: &'a str,
    pub authority_ceiling: Option<CapSet>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountBinding {
    display_name: String,
    key: AccountKey,
    revocation_epoch: String,
    identity_path: String,
    credential_epoch: String,
    authentication: AuthenticationEvidence,
    authority_ceiling: Option<CapSet>,
    purpose: AuthenticationPurpose,
}

impl AccountBinding {
    fn ledger_binding(&self) -> challenges::Binding {
        match &self.purpose {
            AuthenticationPurpose::StepUp { sid } => challenges::Binding::MfaStepUp {
                username: self.display_name.clone(),
                account: self.key.clone(),
                sid: sid.clone(),
            },
            AuthenticationPurpose::Login => challenges::Binding::MfaLogin {
                username: self.display_name.clone(),
                account: self.key.clone(),
            },
        }
    }

    fn purpose(&self) -> MfaPurpose {
        match self.purpose {
            AuthenticationPurpose::StepUp { .. } => MfaPurpose::StepUp,
            AuthenticationPurpose::Login => MfaPurpose::Login,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ceremony {
    owner: AccountBinding,
    max_steps: u16,
    min_poll_interval_ms: i64,
    state: Progress,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
enum Progress {
    ChooseFactor,
    Interaction {
        selected: SelectedFactor,
        waiting: Waiting,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedFactor {
    factor_id: String,
    provider_id: String,
    verifier_digest: String,
    round: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Waiting {
    Challenge {
        private_state: JsonValue,
        challenge: JsonValue,
        response_schema: JsonValue,
    },
    Pending {
        private_state: JsonValue,
        status: JsonValue,
        not_before: i64,
    },
}

fn verifier_digest(verifier: &JsonValue) -> Result<String, AuthError> {
    let encoded = serde_json::to_vec(verifier)
        .map_err(|_error| AuthError::State("invalid MFA verifier".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(encoded)))
}

impl ConsoleAuth {
    pub(super) async fn start_authentication(
        &self,
        state: &Backend,
        start: AuthenticationStart<'_>,
    ) -> Result<AuthenticationResponse, AuthError> {
        let AuthenticationStart {
            account,
            mut credentials,
            primary,
            purpose,
            proof,
            bearer,
            source,
            authority_ceiling,
        } = start;
        self.mfa_limits_for_account(state, &account.key, source)
            .await?;
        let authentication = match &purpose {
            AuthenticationPurpose::StepUp { sid } => {
                let session = read_session(self.session_store.as_ref(), &session_path(sid)?)
                    .await?
                    .ok_or(AuthError::InvalidSession)?;
                if session.authentication.primary != primary {
                    return Err(AuthError::InvalidSession);
                }
                if session.authority_ceiling != authority_ceiling {
                    return Err(AuthError::InvalidSession);
                }
                session.authentication
            }
            AuthenticationPurpose::Login => AuthenticationEvidence {
                primary,
                secondary: None,
            },
        };
        let owner = AccountBinding {
            display_name: account.display_name.clone(),
            key: account.key.clone(),
            revocation_epoch: account.revocation_epoch.clone(),
            identity_path: account.identity.to_string(),
            credential_epoch: credentials.epoch.clone(),
            authentication,
            authority_ceiling,
            purpose,
        };
        self.revalidate_authentication(state, &owner, bearer)
            .await?;
        if credentials.factors.is_empty() {
            if owner.purpose() != MfaPurpose::Login || proof.is_some() {
                return Err(self.required_error(&credentials));
            }
            self.clear_login_failures_for_account(
                &account.key,
                source,
                self.host_runtime.now_millis(),
            );
            clear_account_lockout(state, &account.key).await?;
            let session = self
                .issue_session(
                    state,
                    account,
                    source.into(),
                    owner.authentication,
                    credentials.epoch,
                    owner.authority_ceiling,
                )
                .await?;
            return Ok(AuthenticationResponse::Authenticated { session });
        }
        if let Some(proof) = proof {
            let secondary = match self
                .verify_record(
                    &account.display_name,
                    &mut credentials,
                    proof,
                    owner.purpose(),
                )
                .await
            {
                Ok(secondary) => secondary,
                Err(error) => {
                    return Err(self
                        .mfa_failure_for_account(state, &account.key, source, error)
                        .await);
                }
            };
            return self
                .commit_verified(state, &owner, bearer, source, credentials, secondary)
                .await;
        }
        let payload = Ceremony {
            owner,
            max_steps: self.config.mfa.max_authentication_steps.clamp(1, 32),
            min_poll_interval_ms: self.config.mfa.min_poll_interval_ms.clamp(100, 30_000),
            state: Progress::ChooseFactor,
        };
        let expires_at = self
            .host_runtime
            .now_millis()
            .saturating_add(self.config.mfa.authentication_ttl_ms.clamp(30_000, 300_000));
        let expires_at = payload
            .owner
            .authentication
            .primary
            .valid_until()
            .map_or(expires_at, |until| expires_at.min(until));
        if expires_at <= self.host_runtime.now_millis() {
            return Err(AuthError::InvalidCredentials);
        }
        let token = challenges::issue_continuation(
            &self.host_runtime,
            state,
            &self.config.challenges,
            payload.owner.ledger_binding(),
            source,
            expires_at,
            &payload,
        )
        .await?;
        Ok(self.authentication_progress(token, expires_at, &payload, &credentials))
    }

    async fn revalidate_authentication(
        &self,
        state: &Backend,
        owner: &AccountBinding,
        bearer: Option<&str>,
    ) -> Result<(AccountSnapshot, AccountCredentials), AuthError> {
        owner
            .authentication
            .validate()
            .map_err(|_error| AuthError::InvalidChallenge)?;
        if owner
            .authentication
            .primary
            .valid_until()
            .is_some_and(|until| until <= self.host_runtime.now_millis())
        {
            return Err(AuthError::InvalidChallenge);
        }
        if let Some(principal) = self
            .validate_continuation_bearer(state, &owner.ledger_binding(), bearer)
            .await?
            && principal.authentication != owner.authentication
        {
            return Err(AuthError::InvalidChallenge);
        }
        let account = self
            .current_account(state, &owner.key, Some(&owner.display_name))
            .await?;
        if account.revocation_epoch != owner.revocation_epoch
            || account.identity.to_string() != owner.identity_path
        {
            return Err(AuthError::InvalidChallenge);
        }
        if !account.active {
            return Err(AuthError::AccountUnavailable);
        }
        let record = credentials::read_by_key(state, &owner.key, self.credential_sealer()?).await?;
        if record.epoch != owner.credential_epoch {
            return Err(AuthError::InvalidChallenge);
        }
        if owner
            .authentication
            .primary
            .valid_until()
            .is_some_and(|until| until <= self.host_runtime.now_millis())
        {
            return Err(AuthError::InvalidChallenge);
        }
        Ok((account, record))
    }

    async fn validate_continuation_bearer(
        &self,
        state: &Backend,
        binding: &challenges::Binding,
        bearer: Option<&str>,
    ) -> Result<Option<ConsolePrincipal>, AuthError> {
        match binding {
            challenges::Binding::MfaLogin { .. } => Ok(None),
            challenges::Binding::MfaStepUp { account, sid, .. } => {
                let bearer = bearer.ok_or(AuthError::MissingBearer)?;
                let principal = self.authenticate_token_inner(state, bearer).await?;
                if principal.account_key() != *account
                    || bearer.split_once('.').map(|(id, _)| id) != Some(sid)
                {
                    return Err(AuthError::InvalidChallenge);
                }
                Ok(Some(principal))
            }
            _ => Err(AuthError::InvalidChallenge),
        }
    }

    async fn commit_verified(
        &self,
        state: &Backend,
        owner: &AccountBinding,
        bearer: Option<&str>,
        source: &str,
        record: AccountCredentials,
        secondary: SecondaryAuthentication,
    ) -> Result<AuthenticationResponse, AuthError> {
        let (account, _) = self.revalidate_authentication(state, owner, bearer).await?;
        credentials::write_by_key(state, &owner.key, &record, self.credential_sealer()?).await?;
        self.clear_login_failures_for_account(&owner.key, source, self.host_runtime.now_millis());
        clear_account_lockout(state, &owner.key).await?;
        let session = self
            .issue_session(
                state,
                &account,
                source.into(),
                AuthenticationEvidence {
                    primary: owner.authentication.primary.clone(),
                    secondary: Some(secondary),
                },
                record.epoch,
                owner.authority_ceiling.clone(),
            )
            .await?;
        Ok(AuthenticationResponse::Authenticated { session })
    }

    fn authentication_progress(
        &self,
        continuation: String,
        expires_at: i64,
        ceremony: &Ceremony,
        record: &AccountCredentials,
    ) -> AuthenticationResponse {
        let step = match &ceremony.state {
            Progress::ChooseFactor => AuthenticationStep::ChooseFactor {
                options: MfaOptions {
                    factors: self.factor_summaries(record),
                    recovery_code_available: !record.recovery.is_empty(),
                },
            },
            Progress::Interaction { selected, waiting } => match waiting {
                Waiting::Challenge {
                    challenge,
                    response_schema,
                    ..
                } => AuthenticationStep::Challenge {
                    factor_id: selected.factor_id.clone(),
                    provider_id: selected.provider_id.clone(),
                    challenge: challenge.clone(),
                    response_schema: response_schema.clone(),
                },
                Waiting::Pending {
                    status, not_before, ..
                } => AuthenticationStep::Pending {
                    factor_id: selected.factor_id.clone(),
                    provider_id: selected.provider_id.clone(),
                    status: status.clone(),
                    retry_after_ms: not_before
                        .saturating_sub(self.host_runtime.now_millis())
                        .max(0),
                },
            },
        };
        AuthenticationResponse::Continue(AuthenticationContinuation {
            continuation,
            expires_at,
            step,
        })
    }

    pub(crate) async fn continue_authentication(
        &self,
        boot: &Bootstrap,
        bearer: Option<&str>,
        request: ContinueAuthenticationRequest,
        source: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        let state = boot.kernel().state();
        // This lookup is for audit attribution only. The operation rechecks the token.
        let (username, account, login) =
            match challenges::inspect_owner(&self.host_runtime, state, &request.continuation).await
            {
                Ok(challenges::Binding::MfaLogin { username, account }) => {
                    (Some(username), Some(account), true)
                }
                Ok(challenges::Binding::MfaStepUp {
                    username, account, ..
                }) => (Some(username), Some(account), false),
                _ => (None, None, false),
            };
        let result = self
            .continue_authentication_inner(state, bearer, request, &source)
            .await;
        let result = match (result, account.as_ref()) {
            (Err(error), Some(account)) => Err(self
                .mfa_failure_for_account(state, account, &source, error)
                .await),
            (result, _) => result,
        };
        let (event, outcome, authentication) = match &result {
            Ok(AuthenticationResponse::Authenticated { session }) if login => {
                ("console_login", "ok", Some(&session.authentication))
            }
            Ok(AuthenticationResponse::Authenticated { session }) => (
                "console_credential",
                "step_up",
                Some(&session.authentication),
            ),
            Ok(AuthenticationResponse::Continue(_)) => {
                ("console_credential", "authentication_pending", None)
            }
            Err(error) if login => ("console_login_failed", audit_outcome(error), None),
            Err(error) => ("console_credential", audit_outcome(error), None),
        };
        record_auth_audit(
            boot,
            event,
            username.as_deref(),
            Some(&source),
            outcome,
            authentication,
        )?;
        result
    }

    async fn continue_authentication_inner(
        &self,
        state: &Backend,
        bearer: Option<&str>,
        request: ContinueAuthenticationRequest,
        source: &str,
    ) -> Result<AuthenticationResponse, AuthError> {
        let pending =
            challenges::inspect::<Ceremony>(&self.host_runtime, state, &request.continuation)
                .await?;
        if pending.binding != pending.payload.owner.ledger_binding()
            || !(1..=32).contains(&pending.payload.max_steps)
            || !(100..=30_000).contains(&pending.payload.min_poll_interval_ms)
        {
            return Err(AuthError::InvalidChallenge);
        }
        let (_, record) = self
            .revalidate_authentication(state, &pending.payload.owner, bearer)
            .await?;
        self.mfa_limits_for_account(state, &pending.payload.owner.key, source)
            .await?;
        match (&pending.payload.state, &request.input) {
            (
                Progress::ChooseFactor,
                AuthenticationInput::Proof {
                    proof: MfaProof::Factor { factor_id, .. },
                },
            ) => {
                let factor = record
                    .factors
                    .get(factor_id)
                    .ok_or(AuthError::InvalidCredentials)?;
                self.provider_for(&factor.provider_id, mfa::ProviderOperation::Proof)?;
            }
            (
                Progress::ChooseFactor,
                AuthenticationInput::Proof {
                    proof: MfaProof::RecoveryCode { .. },
                },
            ) => {}
            (Progress::ChooseFactor, AuthenticationInput::SelectFactor { factor_id }) => {
                let factor = record
                    .factors
                    .get(factor_id)
                    .ok_or(AuthError::InvalidMfaRequest)?;
                self.provider_for(&factor.provider_id, mfa::ProviderOperation::Interaction)?;
            }
            (
                Progress::Interaction {
                    selected,
                    waiting: Waiting::Challenge { .. },
                },
                AuthenticationInput::Response { response },
            ) => {
                self.selected_verifier(&record, selected)?;
                self.provider_for(&selected.provider_id, mfa::ProviderOperation::Interaction)?;
                if !mfa::bounded_json(response) {
                    return Err(AuthError::InvalidMfaRequest);
                }
            }
            (
                Progress::Interaction {
                    selected,
                    waiting: Waiting::Pending { not_before, .. },
                },
                AuthenticationInput::Poll {},
            ) => {
                self.selected_verifier(&record, selected)?;
                self.provider_for(&selected.provider_id, mfa::ProviderOperation::Interaction)?;
                if *not_before > self.host_runtime.now_millis() {
                    return Ok(self.authentication_progress(
                        request.continuation,
                        pending.expires_at,
                        &pending.payload,
                        &record,
                    ));
                }
            }
            _ => return Err(AuthError::InvalidMfaRequest),
        }
        // The current host's usage policy must pass before taking round custody.
        // A denied host leaves the continuation usable by an allowed host.
        let round = challenges::claim::<Ceremony>(
            &self.host_runtime,
            state,
            &request.continuation,
            &pending.binding,
        )
        .await?;
        let result = self
            .run_authentication_round(state, bearer, source, &round, request.input)
            .await;
        if result.is_err() {
            // Only this round may retire its slot. A failed cleanup leaves bounded
            // in-flight custody until the original deadline; it cannot resurrect it.
            challenges::retire(state, &round).await?;
        }
        result
    }

    fn selected_verifier<'a>(
        &self,
        record: &'a AccountCredentials,
        selected: &SelectedFactor,
    ) -> Result<&'a credentials::StoredFactor, AuthError> {
        let factor = record
            .factors
            .get(&selected.factor_id)
            .ok_or(AuthError::InvalidChallenge)?;
        if factor.provider_id != selected.provider_id
            || verifier_digest(&factor.verifier)? != selected.verifier_digest
        {
            return Err(AuthError::CredentialConflict);
        }
        Ok(factor)
    }

    async fn run_authentication_round(
        &self,
        state: &Backend,
        bearer: Option<&str>,
        source: &str,
        round: &challenges::Round<Ceremony>,
        input: AuthenticationInput,
    ) -> Result<AuthenticationResponse, AuthError> {
        let ceremony = &round.payload;
        let (_, mut record) = self
            .revalidate_authentication(state, &ceremony.owner, bearer)
            .await?;
        if let AuthenticationInput::Proof { proof } = &input {
            if !matches!(ceremony.state, Progress::ChooseFactor) {
                return Err(AuthError::InvalidChallenge);
            }
            let work = self.verify_record(
                &ceremony.owner.display_name,
                &mut record,
                proof,
                ceremony.owner.purpose(),
            );
            let deadline = crate::host_time::after(
                &self.host_runtime,
                remaining_timeout(self.host_runtime.now_millis(), round.expires_at)?,
            )
            .map_err(|_error| AuthError::State("MFA provider timed out".into()))?;
            let secondary = crate::host_time::timeout_at(&self.host_runtime, deadline, work)
                .await
                .map_err(|_error| AuthError::State("MFA provider timed out".into()))??;
            self.revalidate_authentication(state, &ceremony.owner, bearer)
                .await?;
            challenges::finish(&self.host_runtime, state, round).await?;
            return self
                .commit_verified(state, &ceremony.owner, bearer, source, record, secondary)
                .await;
        }
        let (mut selected, provider_input) = match (&ceremony.state, input) {
            (Progress::ChooseFactor, AuthenticationInput::SelectFactor { factor_id }) => {
                let factor = record
                    .factors
                    .get(&factor_id)
                    .ok_or(AuthError::InvalidMfaRequest)?;
                (
                    SelectedFactor {
                        factor_id,
                        provider_id: factor.provider_id.clone(),
                        verifier_digest: verifier_digest(&factor.verifier)?,
                        round: 0,
                    },
                    None,
                )
            }
            (
                Progress::Interaction { selected, .. },
                AuthenticationInput::Response { response },
            ) => (
                selected.clone(),
                Some(MfaInteractionInput::Response { response }),
            ),
            (Progress::Interaction { selected, .. }, AuthenticationInput::Poll {}) => {
                (selected.clone(), Some(MfaInteractionInput::Poll {}))
            }
            _ => return Err(AuthError::InvalidMfaRequest),
        };
        selected.round = selected
            .round
            .checked_add(1)
            .ok_or(AuthError::InvalidChallenge)?;
        if selected.round > ceremony.max_steps {
            return Err(AuthError::InvalidChallenge);
        }
        let factor = self.selected_verifier(&record, &selected)?;
        let provider =
            self.provider_for(&selected.provider_id, mfa::ProviderOperation::Interaction)?;
        let context = MfaInteractionContext {
            factor: self.mfa_context(
                &ceremony.owner.display_name,
                &ceremony.owner.key,
                &selected.factor_id,
                &factor.label,
                ceremony.owner.purpose(),
            ),
            ceremony_id: &round.ceremony_id,
            round: selected.round,
            expires_at: round.expires_at,
        };
        let timeout = remaining_timeout(self.host_runtime.now_millis(), round.expires_at)?;
        let work = match (&ceremony.state, provider_input.as_ref()) {
            (Progress::ChooseFactor, None) => provider
                .implementation
                .begin_authentication(context, &factor.verifier),
            (Progress::Interaction { waiting, .. }, Some(input)) => {
                let private_state = match waiting {
                    Waiting::Challenge { private_state, .. }
                    | Waiting::Pending { private_state, .. } => private_state,
                };
                provider.implementation.continue_authentication(
                    context,
                    &factor.verifier,
                    private_state,
                    input,
                )
            }
            _ => return Err(AuthError::InvalidChallenge),
        };
        let deadline = crate::host_time::after(&self.host_runtime, timeout)
            .map_err(|_error| AuthError::State("MFA provider timed out".into()))?;
        let output = crate::host_time::timeout_at(&self.host_runtime, deadline, work)
            .await
            .map_err(|_error| AuthError::State("MFA provider timed out".into()))?
            .map_err(mfa::provider_error)?;
        let verified_at = self.host_runtime.now_millis();
        let (_, mut current) = self
            .revalidate_authentication(state, &ceremony.owner, bearer)
            .await?;
        self.selected_verifier(&current, &selected)?;
        let waiting = match output {
            MfaInteractionStep::Verified { next_verifier } => {
                if !mfa::bounded_json(&next_verifier) {
                    return Err(AuthError::State("invalid MFA verifier".into()));
                }
                let factor = current
                    .factors
                    .get_mut(&selected.factor_id)
                    .ok_or(AuthError::InvalidChallenge)?;
                factor.verifier = next_verifier;
                factor.last_used_at = Some(
                    verified_at
                        .max(factor.created_at)
                        .max(factor.last_used_at.unwrap_or_default()),
                );
                // Cancellation and success race at this single consumption point.
                // Subsequent credential/session commits are not a distributed transaction.
                challenges::finish(&self.host_runtime, state, round).await?;
                return self
                    .commit_verified(
                        state,
                        &ceremony.owner,
                        bearer,
                        source,
                        current,
                        SecondaryAuthentication::Factor {
                            factor_id: selected.factor_id,
                            provider_id: selected.provider_id,
                            verified_at,
                        },
                    )
                    .await;
            }
            MfaInteractionStep::Challenge {
                private_state,
                challenge,
                response_schema,
            } => {
                if !mfa::bounded_json(&private_state)
                    || !mfa::bounded_json(&challenge)
                    || !mfa::valid_schema(&response_schema)
                {
                    return Err(AuthError::State("invalid MFA interaction state".into()));
                }
                Waiting::Challenge {
                    private_state,
                    challenge,
                    response_schema,
                }
            }
            MfaInteractionStep::Pending {
                private_state,
                status,
                retry_after_ms,
            } => {
                if !mfa::bounded_json(&private_state) || !mfa::bounded_json(&status) {
                    return Err(AuthError::State("invalid MFA interaction state".into()));
                }
                let not_before = self
                    .host_runtime
                    .now_millis()
                    .saturating_add(retry_after_ms.max(ceremony.min_poll_interval_ms));
                if not_before >= round.expires_at {
                    return Err(AuthError::InvalidChallenge);
                }
                Waiting::Pending {
                    private_state,
                    status,
                    not_before,
                }
            }
        };
        if selected.round >= ceremony.max_steps {
            return Err(AuthError::InvalidChallenge);
        }
        let mut next = ceremony.clone();
        next.state = Progress::Interaction { selected, waiting };
        let token = challenges::advance(
            &self.host_runtime,
            state,
            &self.config.challenges,
            round,
            &next,
        )
        .await?;
        Ok(self.authentication_progress(token, round.expires_at, &next, &current))
    }

    pub(crate) async fn cancel_authentication(
        &self,
        boot: &Bootstrap,
        bearer: Option<&str>,
        request: CancelAuthenticationRequest,
        source: String,
    ) -> Result<(), AuthError> {
        let state = boot.kernel().state();
        let binding =
            challenges::inspect_owner(&self.host_runtime, state, &request.continuation).await;
        let username = match &binding {
            Ok(
                challenges::Binding::MfaLogin { username, .. }
                | challenges::Binding::MfaStepUp { username, .. },
            ) => Some(username.clone()),
            _ => None,
        };
        let result = async {
            let binding = binding?;
            let _principal = self
                .validate_continuation_bearer(state, &binding, bearer)
                .await?;
            challenges::cancel(&self.host_runtime, state, &request.continuation, &binding).await
        }
        .await;
        let outcome = match &result {
            Ok(()) => "authentication_cancelled",
            Err(error) => audit_outcome(error),
        };
        record_auth_audit(
            boot,
            "console_credential",
            username.as_deref(),
            Some(&source),
            outcome,
            None,
        )?;
        result
    }
}

fn remaining_timeout(now_millis: i64, expires_at: i64) -> Result<Duration, AuthError> {
    let remaining = expires_at.saturating_sub(now_millis);
    if remaining <= 0 {
        return Err(AuthError::InvalidChallenge);
    }
    Ok(Duration::from_millis(remaining.min(10_000) as u64))
}

#[cfg(test)]
mod tests;
