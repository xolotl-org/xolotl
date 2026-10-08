//! Enrollment is a separate account-writing ceremony, not a login continuation.
//! Its vault row is the single claim and publication point for every round.

use super::*;

// The authenticated caller and the credential snapshot must travel together
// through each enrollment round. The snapshot is consumed by the round.
pub(super) struct EnrollmentInvocation<'a> {
    pub(super) boot: &'a Bootstrap,
    pub(super) bearer: &'a str,
    pub(super) principal: &'a ConsolePrincipal,
    pub(super) record: AccountCredentials,
    pub(super) sid: &'a str,
}

fn remaining_provider_time(now_millis: i64, expires_at: i64) -> Result<Duration, AuthError> {
    let remaining = expires_at.saturating_sub(now_millis);
    let millis = u64::try_from(remaining)
        .ok()
        .filter(|millis| *millis > 0)
        .ok_or(AuthError::InvalidChallenge)?;
    Ok(Duration::from_millis(millis.min(10_000)))
}

fn waiting_step(
    step: MfaEnrollmentStep,
    pending_supported: bool,
    expires_at: i64,
    min_poll_interval_ms: i64,
    now: i64,
) -> Result<(EnrollmentWaiting, MfaEnrollmentProgress), AuthError> {
    match step {
        MfaEnrollmentStep::Challenge {
            private_state,
            setup,
            response_schema,
        } => {
            if !bounded_json(&private_state)
                || !bounded_json(&setup)
                || !valid_schema(&response_schema)
            {
                return Err(AuthError::State("invalid MFA enrollment step".into()));
            }
            Ok((
                EnrollmentWaiting::Challenge {
                    private_state,
                    setup: setup.clone(),
                    response_schema: response_schema.clone(),
                },
                MfaEnrollmentProgress::Challenge {
                    setup,
                    response_schema,
                },
            ))
        }
        MfaEnrollmentStep::Pending {
            private_state,
            status,
            retry_after_ms,
        } => {
            if !pending_supported || !bounded_json(&private_state) || !bounded_json(&status) {
                return Err(AuthError::State("invalid MFA enrollment step".into()));
            }
            let retry_after_ms = retry_after_ms.max(min_poll_interval_ms);
            let not_before = now.saturating_add(retry_after_ms);
            if not_before >= expires_at {
                return Err(AuthError::State(
                    "MFA enrollment cannot continue before expiry".into(),
                ));
            }
            Ok((
                EnrollmentWaiting::Pending {
                    private_state,
                    status: status.clone(),
                    not_before,
                },
                MfaEnrollmentProgress::Pending {
                    status,
                    retry_after_ms,
                },
            ))
        }
        MfaEnrollmentStep::Verified { .. } => Err(AuthError::State(
            "MFA enrollment completed without a continuation".into(),
        )),
    }
}

fn response(pending: &PendingEnrollment, step: MfaEnrollmentProgress) -> MfaResponse {
    MfaResponse::Enrollment {
        challenge_id: pending.id.clone(),
        factor_id: pending.factor_id.clone(),
        provider_id: pending.provider_id.clone(),
        label: pending.label.clone(),
        expires_at: pending.expires_at,
        step,
    }
}

fn current_step(pending: &PendingEnrollment, now: i64) -> MfaEnrollmentProgress {
    match (&pending.waiting, &pending.phase) {
        (EnrollmentWaiting::Starting {}, _) => MfaEnrollmentProgress::Starting {},
        (_, EnrollmentPhase::InFlight { .. }) => MfaEnrollmentProgress::InFlight {},
        (
            EnrollmentWaiting::Challenge {
                setup,
                response_schema,
                ..
            },
            EnrollmentPhase::Ready {},
        ) => MfaEnrollmentProgress::Challenge {
            setup: setup.clone(),
            response_schema: response_schema.clone(),
        },
        (
            EnrollmentWaiting::Pending {
                status, not_before, ..
            },
            EnrollmentPhase::Ready {},
        ) => MfaEnrollmentProgress::Pending {
            status: status.clone(),
            retry_after_ms: not_before.saturating_sub(now).max(0),
        },
    }
}

// Restore the displaced ready round only while this exact Starting claim still
// owns the account slot. A competing cancel, Begin or credential CAS must win
// without this cleanup reviving an older enrollment.
async fn rollback_begin_claim(
    runtime: &xolotl_kernel::host::HostRuntime,
    state: &Backend,
    key: &AccountKey,
    epoch: &str,
    claimed: &PendingEnrollment,
    mut previous: Option<PendingEnrollment>,
    sealer: &CredentialSealer,
) -> Result<(), AuthError> {
    for _ in 0..3 {
        let mut current = read_by_key(state, key, sealer).await?;
        if current.epoch != epoch || current.pending.as_ref() != Some(claimed) {
            return Ok(());
        }
        current.pending = previous
            .take()
            .filter(|ready| ready.expires_at > runtime.now_millis());
        let restore = if current.pending.is_some() {
            write_reserving_enrollment_claim_by_key(state, key, &current, sealer).await
        } else {
            write_by_key(state, key, &current, sealer).await
        };
        match restore {
            Ok(()) => return Ok(()),
            Err(AuthError::CredentialConflict) => {
                previous = current.pending.take();
            }
            Err(AuthError::InvalidCredentialRequest) if current.pending.is_some() => {
                // An unrelated credential update may have consumed the space
                // needed to restore and later claim the old round. Clear ours.
                current.pending = None;
                match write_by_key(state, key, &current, sealer).await {
                    Ok(()) => return Ok(()),
                    Err(AuthError::CredentialConflict) => {}
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(AuthError::CredentialConflict)
}

impl ConsoleAuth {
    pub(super) fn current_factor_enrollment(
        &self,
        record: &AccountCredentials,
        sid: &str,
    ) -> MfaResponse {
        let Some(pending) = record.pending.as_ref().filter(|pending| {
            pending.sid == sid && pending.expires_at > self.host_runtime.now_millis()
        }) else {
            return MfaResponse::NoEnrollment;
        };
        response(
            pending,
            current_step(pending, self.host_runtime.now_millis()),
        )
    }

    pub(super) async fn begin_factor_enrollment(
        &self,
        invocation: EnrollmentInvocation<'_>,
        provider_id: String,
        label: String,
        replace_factor_id: Option<String>,
        input: Option<JsonValue>,
    ) -> Result<MfaResponse, AuthError> {
        let EnrollmentInvocation {
            boot,
            bearer,
            principal,
            mut record,
            sid,
        } = invocation;
        let state = boot.kernel().state();
        let account_key = principal.account_key();
        validate_label(&label).map_err(|_error| AuthError::InvalidMfaRequest)?;
        let provider = self.provider_for(&provider_id, ProviderOperation::Enrollment)?;
        let descriptor = provider
            .descriptor
            .enrollment
            .as_ref()
            .ok_or(AuthError::MfaOperationUnavailable)?;
        if input.is_some() != descriptor.begin_schema.is_some()
            || input.as_ref().is_some_and(|value| !bounded_json(value))
        {
            return Err(AuthError::InvalidMfaRequest);
        }
        match &replace_factor_id {
            Some(id) => {
                let factor = record.factors.get(id).ok_or(AuthError::InvalidMfaRequest)?;
                if factor.provider_id != provider_id {
                    return Err(AuthError::InvalidMfaRequest);
                }
            }
            None if record.factors.len() >= MAX_FACTORS => {
                return Err(AuthError::InvalidMfaRequest);
            }
            None => {}
        }
        let mut factor_id = random_token(18)?;
        while record.factors.contains_key(&factor_id)
            || record
                .pending
                .as_ref()
                .is_some_and(|pending| pending.factor_id == factor_id)
        {
            factor_id = random_token(18)?;
        }
        let expires_at = self
            .host_runtime
            .now_millis()
            .saturating_add(self.config.mfa.enrollment_ttl_ms.clamp(30_000, 900_000));
        let previous = record.pending.take().filter(|pending| {
            matches!(pending.phase, EnrollmentPhase::Ready {})
                && pending.expires_at > self.host_runtime.now_millis()
        });
        record.pending = Some(PendingEnrollment {
            id: random_token(18)?,
            sid: sid.into(),
            factor_id,
            provider_id,
            label,
            replace_factor_id,
            expires_at,
            round: 0,
            waiting: EnrollmentWaiting::Starting {},
            phase: EnrollmentPhase::InFlight {
                claim_id: random_token(18)?,
            },
        });
        write_by_key(state, &account_key, &record, self.credential_sealer()?).await?;
        let claimed = record.pending.as_ref().ok_or(AuthError::InvalidChallenge)?;
        let preflight = async {
            let current = read_by_key(state, &account_key, self.credential_sealer()?).await?;
            if current.epoch != record.epoch || current.pending.as_ref() != Some(claimed) {
                return Err(AuthError::CredentialConflict);
            }
            self.revalidate_mfa_management(boot, bearer, principal, &current)
                .await?;
            remaining_provider_time(self.host_runtime.now_millis(), expires_at)?;
            Ok(())
        }
        .await;
        if let Err(error) = preflight {
            rollback_begin_claim(
                &self.host_runtime,
                state,
                &account_key,
                &record.epoch,
                claimed,
                previous,
                self.credential_sealer()?,
            )
            .await?;
            return Err(error);
        }
        let context = MfaEnrollmentContext {
            factor: self.mfa_context(
                &principal.username,
                &account_key,
                &claimed.factor_id,
                &claimed.label,
                MfaPurpose::Enrollment,
            ),
            ceremony_id: &claimed.factor_id,
            round: 1,
            expires_at,
        };
        let timeout = match remaining_provider_time(self.host_runtime.now_millis(), expires_at) {
            Ok(timeout) => timeout,
            Err(error) => {
                rollback_begin_claim(
                    &self.host_runtime,
                    state,
                    &account_key,
                    &record.epoch,
                    claimed,
                    previous,
                    self.credential_sealer()?,
                )
                .await?;
                return Err(error);
            }
        };
        let deadline = match crate::host_time::after(&self.host_runtime, timeout) {
            Ok(deadline) => deadline,
            Err(_error) => {
                rollback_begin_claim(
                    &self.host_runtime,
                    state,
                    &account_key,
                    &record.epoch,
                    claimed,
                    previous,
                    self.credential_sealer()?,
                )
                .await?;
                return Err(AuthError::State("MFA provider timed out".into()));
            }
        };
        let step = crate::host_time::timeout_at(
            &self.host_runtime,
            deadline,
            provider
                .implementation
                .begin_enrollment(context, input.as_ref()),
        )
        .await
        .map_err(|_error| AuthError::State("MFA provider timed out".into()))
        .and_then(|result| result.map_err(provider_error));
        let step = match step {
            Ok(step) => step,
            Err(error) => {
                if matches!(error, AuthError::InvalidMfaRequest) {
                    rollback_begin_claim(
                        &self.host_runtime,
                        state,
                        &account_key,
                        &record.epoch,
                        claimed,
                        previous,
                        self.credential_sealer()?,
                    )
                    .await?;
                }
                return Err(error);
            }
        };
        let (waiting, public_step) = match waiting_step(
            step,
            descriptor.pending_schema.is_some(),
            expires_at,
            self.config.mfa.min_poll_interval_ms.clamp(100, 30_000),
            self.host_runtime.now_millis(),
        ) {
            Ok(step) => step,
            Err(error) => {
                rollback_begin_claim(
                    &self.host_runtime,
                    state,
                    &account_key,
                    &record.epoch,
                    claimed,
                    previous,
                    self.credential_sealer()?,
                )
                .await?;
                return Err(error);
            }
        };
        let ready = async {
            let mut current = read_by_key(state, &account_key, self.credential_sealer()?).await?;
            if current.epoch != record.epoch || current.pending.as_ref() != Some(claimed) {
                return Err(AuthError::CredentialConflict);
            }
            self.revalidate_mfa_management(boot, bearer, principal, &current)
                .await?;
            if expires_at <= self.host_runtime.now_millis() {
                return Err(AuthError::InvalidChallenge);
            }
            let pending = current
                .pending
                .as_mut()
                .ok_or(AuthError::InvalidChallenge)?;
            pending.round = 1;
            pending.waiting = waiting;
            pending.phase = EnrollmentPhase::Ready {};
            Ok(current)
        }
        .await;
        let current = match ready {
            Ok(current) => current,
            Err(error) => {
                rollback_begin_claim(
                    &self.host_runtime,
                    state,
                    &account_key,
                    &record.epoch,
                    claimed,
                    previous,
                    self.credential_sealer()?,
                )
                .await?;
                return Err(error);
            }
        };
        if let Err(error) = write_reserving_enrollment_claim_by_key(
            state,
            &account_key,
            &current,
            self.credential_sealer()?,
        )
        .await
        {
            if matches!(
                error,
                AuthError::InvalidCredentialRequest | AuthError::CredentialConflict
            ) {
                rollback_begin_claim(
                    &self.host_runtime,
                    state,
                    &account_key,
                    &record.epoch,
                    claimed,
                    previous,
                    self.credential_sealer()?,
                )
                .await?;
            }
            // A backend error may mean the publication committed but its
            // acknowledgment was lost; leave the claim/state for reconciliation.
            return Err(error);
        }
        let pending = current
            .pending
            .as_ref()
            .ok_or(AuthError::InvalidChallenge)?;
        Ok(response(pending, public_step))
    }

    pub(super) async fn continue_factor_enrollment(
        &self,
        invocation: EnrollmentInvocation<'_>,
        challenge_id: String,
        input: MfaInteractionInput,
        source: String,
    ) -> Result<MfaResponse, AuthError> {
        let EnrollmentInvocation {
            boot,
            bearer,
            principal,
            mut record,
            sid,
        } = invocation;
        let state = boot.kernel().state();
        let account_key = principal.account_key();
        let pending = record.pending.as_ref().ok_or(AuthError::InvalidChallenge)?;
        if pending.id != challenge_id
            || pending.sid != sid
            || pending.expires_at <= self.host_runtime.now_millis()
            || !matches!(pending.phase, EnrollmentPhase::Ready {})
        {
            return Err(AuthError::InvalidChallenge);
        }
        let provider = self.provider_for(&pending.provider_id, ProviderOperation::Enrollment)?;
        if pending.round >= self.config.mfa.max_enrollment_steps.clamp(2, 32) {
            return Err(AuthError::MfaOperationUnavailable);
        }
        match (&pending.waiting, &input) {
            (EnrollmentWaiting::Challenge { .. }, MfaInteractionInput::Response { response }) => {
                if !bounded_json(response) {
                    return Err(self
                        .mfa_failure_for_account(
                            state,
                            &account_key,
                            &source,
                            AuthError::InvalidCredentials,
                        )
                        .await);
                }
            }
            (
                EnrollmentWaiting::Pending {
                    not_before, status, ..
                },
                MfaInteractionInput::Poll {},
            ) if self.host_runtime.now_millis() < *not_before => {
                return Ok(response(
                    pending,
                    MfaEnrollmentProgress::Pending {
                        status: status.clone(),
                        retry_after_ms: not_before.saturating_sub(self.host_runtime.now_millis()),
                    },
                ));
            }
            (EnrollmentWaiting::Pending { .. }, MfaInteractionInput::Poll {}) => {}
            _ => return Err(AuthError::InvalidMfaRequest),
        }
        self.revalidate_mfa_management(boot, bearer, principal, &record)
            .await?;
        let claim_id = random_token(18)?;
        record
            .pending
            .as_mut()
            .ok_or(AuthError::InvalidChallenge)?
            .phase = EnrollmentPhase::InFlight { claim_id };
        write_by_key(state, &account_key, &record, self.credential_sealer()?).await?;
        let pending = record.pending.as_ref().ok_or(AuthError::InvalidChallenge)?;
        let preflight = self
            .revalidate_mfa_management(boot, bearer, principal, &record)
            .await
            .and_then(|_account| {
                remaining_provider_time(self.host_runtime.now_millis(), pending.expires_at)?;
                self.provider_for(&pending.provider_id, ProviderOperation::Enrollment)
                    .map(|_provider| ())
            });
        if let Err(error) = preflight {
            release_enrollment_claim(state, &account_key, &record, self.credential_sealer()?)
                .await?;
            return Err(error);
        }
        let context = MfaEnrollmentContext {
            factor: self.mfa_context(
                &principal.username,
                &account_key,
                &pending.factor_id,
                &pending.label,
                MfaPurpose::Enrollment,
            ),
            ceremony_id: &pending.factor_id,
            round: pending.round + 1,
            expires_at: pending.expires_at,
        };
        let deadline = crate::host_time::after(
            &self.host_runtime,
            remaining_provider_time(self.host_runtime.now_millis(), pending.expires_at)?,
        )
        .map_err(|_error| AuthError::State("MFA provider timed out".into()))?;
        let result = crate::host_time::timeout_at(
            &self.host_runtime,
            deadline,
            provider.implementation.continue_enrollment(
                context,
                pending
                    .waiting
                    .private_state()
                    .ok_or(AuthError::InvalidChallenge)?,
                &input,
            ),
        )
        .await
        .map_err(|_error| AuthError::State("MFA provider timed out".into()))
        .and_then(|result| result.map_err(provider_error));
        let step = match result {
            Ok(step) => step,
            Err(error) => {
                let retryable = matches!(
                    error,
                    AuthError::InvalidCredentials | AuthError::InvalidMfaRequest
                );
                let error = self
                    .mfa_failure_for_account(state, &account_key, &source, error)
                    .await;
                if retryable {
                    release_enrollment_claim(
                        state,
                        &account_key,
                        &record,
                        self.credential_sealer()?,
                    )
                    .await?;
                }
                return Err(error);
            }
        };
        if pending.expires_at <= self.host_runtime.now_millis() {
            return Err(AuthError::InvalidChallenge);
        }
        match step {
            MfaEnrollmentStep::Verified { verifier } => {
                self.finish_factor_enrollment(boot, bearer, principal, record, verifier, source)
                    .await
            }
            step => {
                if pending.round.saturating_add(1)
                    >= self.config.mfa.max_enrollment_steps.clamp(2, 32)
                {
                    return Err(AuthError::State(
                        "MFA enrollment exceeded step limit".into(),
                    ));
                }
                let descriptor = provider
                    .descriptor
                    .enrollment
                    .as_ref()
                    .ok_or(AuthError::MfaOperationUnavailable)?;
                let (waiting, public_step) = waiting_step(
                    step,
                    descriptor.pending_schema.is_some(),
                    pending.expires_at,
                    self.config.mfa.min_poll_interval_ms.clamp(100, 30_000),
                    self.host_runtime.now_millis(),
                )?;
                let claimed = record.pending.take().ok_or(AuthError::InvalidChallenge)?;
                let mut current =
                    read_by_key(state, &account_key, self.credential_sealer()?).await?;
                if current.epoch != record.epoch || current.pending.as_ref() != Some(&claimed) {
                    return Err(AuthError::CredentialConflict);
                }
                self.revalidate_mfa_management(boot, bearer, principal, &current)
                    .await?;
                let next = current
                    .pending
                    .as_mut()
                    .ok_or(AuthError::InvalidChallenge)?;
                next.id = random_token(18)?;
                next.round = next.round.saturating_add(1);
                next.waiting = waiting;
                next.phase = EnrollmentPhase::Ready {};
                write_reserving_enrollment_claim_by_key(
                    state,
                    &account_key,
                    &current,
                    self.credential_sealer()?,
                )
                .await?;
                Ok(response(
                    current
                        .pending
                        .as_ref()
                        .ok_or(AuthError::InvalidChallenge)?,
                    public_step,
                ))
            }
        }
    }

    async fn finish_factor_enrollment(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        principal: &ConsolePrincipal,
        mut claimed_record: AccountCredentials,
        verifier: JsonValue,
        source: String,
    ) -> Result<MfaResponse, AuthError> {
        if !bounded_json(&verifier) {
            return Err(AuthError::State("invalid MFA verifier".into()));
        }
        let state = boot.kernel().state();
        let account_key = principal.account_key();
        let pending = claimed_record
            .pending
            .take()
            .ok_or(AuthError::InvalidChallenge)?;
        let mut current = read_by_key(state, &account_key, self.credential_sealer()?).await?;
        if current.authority_id != claimed_record.authority_id
            || current.account_id != claimed_record.account_id
            || current.epoch != claimed_record.epoch
            || current.pending.as_ref() != Some(&pending)
        {
            return Err(AuthError::CredentialConflict);
        }
        let account = self
            .revalidate_mfa_management(boot, bearer, principal, &current)
            .await?;
        if pending.expires_at <= self.host_runtime.now_millis() {
            return Err(AuthError::InvalidChallenge);
        }
        if current.factors.contains_key(&pending.factor_id)
            || (pending.replace_factor_id.is_none() && current.factors.len() >= MAX_FACTORS)
        {
            return Err(AuthError::InvalidMfaRequest);
        }
        let mut recovery_codes = None;
        if current.factors.is_empty() {
            recovery_codes = Some(new_recovery_codes(&mut current)?);
        }
        if let Some(id) = pending.replace_factor_id {
            let replaced = current
                .factors
                .remove(&id)
                .ok_or(AuthError::InvalidMfaRequest)?;
            if replaced.provider_id != pending.provider_id {
                return Err(AuthError::InvalidMfaRequest);
            }
        }
        current.factors.insert(
            pending.factor_id,
            StoredFactor {
                provider_id: pending.provider_id,
                label: pending.label,
                created_at: self.host_runtime.now_millis(),
                last_used_at: None,
                verifier,
            },
        );
        current.rotate_epoch()?;
        write_by_key(state, &account_key, &current, self.credential_sealer()?).await?;
        let session = self
            .issue_session(
                state,
                &account,
                source,
                principal.authentication.clone(),
                current.epoch,
                principal.authority_ceiling.clone(),
            )
            .await?;
        Ok(MfaResponse::Updated {
            session,
            recovery_codes,
        })
    }

    pub(super) async fn cancel_factor_enrollment(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        principal: &ConsolePrincipal,
        mut record: AccountCredentials,
        sid: &str,
        challenge_id: &str,
    ) -> Result<MfaResponse, AuthError> {
        let pending = record.pending.as_ref().ok_or(AuthError::InvalidChallenge)?;
        if pending.id != challenge_id || pending.sid != sid {
            return Err(AuthError::InvalidChallenge);
        }
        record.pending = None;
        self.revalidate_mfa_management(boot, bearer, principal, &record)
            .await?;
        write_by_key(
            boot.kernel().state(),
            &principal.account_key(),
            &record,
            self.credential_sealer()?,
        )
        .await?;
        Ok(MfaResponse::Canceled)
    }
}
