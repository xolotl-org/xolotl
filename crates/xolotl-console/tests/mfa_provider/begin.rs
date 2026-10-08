//! Provider-specific enrollment choices are discovered and checked at the host boundary.

use super::*;

struct DeviceChoice {
    factor: Arc<SignedFactor>,
    observed: Mutex<Vec<String>>,
}

impl MfaProvider for DeviceChoice {
    fn descriptor(&self) -> MfaProviderDescriptor {
        let mut descriptor = self.factor.descriptor();
        if let Some(enrollment) = descriptor.enrollment.as_mut() {
            enrollment.begin_schema = Some(json!({
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "properties": {"device": {"type": "string"}},
                        "required": ["device"],
                        "additionalProperties": false
                    }
                ]
            }));
        }
        descriptor
    }

    fn begin_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        input: Option<&'a Value>,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            let input = input.ok_or(MfaProviderError::InvalidInput)?;
            let device = if input.is_null() {
                "default"
            } else {
                input
                    .get("device")
                    .and_then(Value::as_str)
                    .ok_or(MfaProviderError::InvalidInput)?
            };
            self.observed
                .lock()
                .map_err(|_error| MfaProviderError::Unavailable)?
                .push(device.into());
            if device == "blocked" {
                return Err(MfaProviderError::InvalidInput);
            }
            if device == "unavailable" {
                return Err(MfaProviderError::Unavailable);
            }
            let MfaEnrollmentStep::Challenge {
                private_state,
                mut setup,
                response_schema,
            } = self.factor.begin_enrollment(context, None).await?
            else {
                return Err(MfaProviderError::InvalidState);
            };
            setup["selected_device"] = json!(device);
            Ok(MfaEnrollmentStep::Challenge {
                private_state,
                setup,
                response_schema,
            })
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        private_state: &'a Value,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        self.factor
            .continue_enrollment(context, private_state, input)
    }

    fn verify_proof<'a>(
        &'a self,
        context: MfaContext<'a>,
        verifier: &'a Value,
        proof: &'a Value,
    ) -> MfaFuture<'a, Value> {
        self.factor.verify_proof(context, verifier, proof)
    }
}

async fn begin(
    service: &ConsoleService,
    bearer: &str,
    provider_id: &str,
    input: Option<Value>,
) -> Result<MfaResponse, xolotl_console::ConsoleFailure> {
    service
        .mfa(
            bearer,
            MfaRequest::Begin {
                provider_id: provider_id.into(),
                label: "My device".into(),
                replace_factor_id: None,
                input,
            },
            "test".into(),
        )
        .await
}

#[tokio::test]
async fn begin_choices_are_discoverable_bounded_and_borrowed_for_one_provider_call()
-> anyhow::Result<()> {
    let (boot, mut config, _original_service, factor, _key) = fixture().await?;
    let provider = Arc::new(DeviceChoice {
        factor,
        observed: Mutex::new(Vec::new()),
    });
    config.auth.mfa.providers = vec![provider.clone()];
    let service = ConsoleService::new(ConsoleState::with_config(boot, config)?);
    let descriptor = service
        .mfa_providers()
        .into_iter()
        .find(|summary| summary.descriptor.provider_id == "signed_device")
        .context("installed provider")?
        .descriptor;
    ensure!(
        descriptor
            .enrollment
            .context("enrollment")?
            .begin_schema
            .is_some()
    );
    let bearer = service
        .login(login(None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("primary login"))?
        .token;

    for missing_or_large in [None, Some(json!({"device":"x".repeat(16 * 1024)}))] {
        let error = begin(&service, &bearer, "signed_device", missing_or_large)
            .await
            .err()
            .context("host rejects missing or oversized begin input")?;
        ensure!(error.code == ConsoleErrorCode::BadRequest);
    }
    ensure!(
        provider
            .observed
            .lock()
            .map_err(|_error| anyhow::anyhow!("observations poisoned"))?
            .is_empty()
    );

    let MfaResponse::Enrollment {
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = begin(
        &service,
        &bearer,
        "signed_device",
        Some(json!({"device":"phone"})),
    )
    .await?
    else {
        anyhow::bail!("device choice enrollment");
    };
    ensure!(setup["selected_device"] == "phone");

    let MfaResponse::Enrollment {
        challenge_id: previous_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = begin(&service, &bearer, "signed_device", Some(Value::Null)).await?
    else {
        anyhow::bail!("null is a present provider input");
    };
    ensure!(setup["selected_device"] == "default");
    let error = begin(
        &service,
        &bearer,
        "signed_device",
        Some(json!({"device":"blocked"})),
    )
    .await
    .err()
    .context("provider semantic validation")?;
    ensure!(error.code == ConsoleErrorCode::BadRequest);
    let MfaResponse::Enrollment { challenge_id, .. } = service
        .mfa(&bearer, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("invalid replacement preserves the previous enrollment");
    };
    ensure!(challenge_id == previous_id);
    {
        let observed = provider
            .observed
            .lock()
            .map_err(|_error| anyhow::anyhow!("observations poisoned"))?;
        ensure!(
            observed.iter().map(String::as_str).collect::<Vec<_>>()
                == ["phone", "default", "blocked"]
        );
    }

    let error = begin(&service, &bearer, "totp", Some(json!({"device":"phone"})))
        .await
        .err()
        .context("TOTP takes no begin input")?;
    ensure!(error.code == ConsoleErrorCode::BadRequest);

    let _error = begin(
        &service,
        &bearer,
        "signed_device",
        Some(json!({"device":"unavailable"})),
    )
    .await
    .err()
    .context("provider result may have external side effects")?;
    let MfaResponse::Enrollment {
        challenge_id,
        step: MfaEnrollmentProgress::Starting {},
        ..
    } = service
        .mfa(&bearer, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("uncertain Begin retains the Starting claim");
    };
    ensure!(challenge_id != previous_id);
    Ok(())
}
