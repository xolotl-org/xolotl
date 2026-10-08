use super::*;
use anyhow::ensure;

#[test]
fn enrollment_begin_preserves_json_null_and_redacts_provider_input() -> anyhow::Result<()> {
    let request = serde_json::json!({
        "operation": "begin",
        "provider_id": "device",
        "label": "Tablet",
        "input": null
    });
    let with_null: MfaRequest = serde_json::from_value(request.clone())?;
    ensure!(matches!(
        &with_null,
        MfaRequest::Begin {
            input: Some(Value::Null),
            ..
        }
    ));
    ensure!(serde_json::to_value(&with_null)? == request);
    let without_input: MfaRequest = serde_json::from_value(serde_json::json!({
        "operation": "begin",
        "provider_id": "device",
        "label": "Tablet"
    }))?;
    ensure!(matches!(
        without_input,
        MfaRequest::Begin { input: None, .. }
    ));
    let sensitive = MfaRequest::Begin {
        provider_id: "device".into(),
        label: "Tablet".into(),
        replace_factor_id: None,
        input: Some(serde_json::json!({"secret":"do-not-log-this"})),
    };
    ensure!(!format!("{sensitive:?}").contains("do-not-log-this"));
    Ok(())
}

#[test]
fn provider_usage_configuration_defaults_each_permission_independently() -> anyhow::Result<()> {
    let config: ConsoleMfaConfig = serde_json::from_value(serde_json::json!({
        "provider_usage": {
            "totp": {"allow_enrollment": false},
            "external_device": {"allow_authentication": false},
            "future_device": {}
        }
    }))?;
    ensure!(
        config.provider_usage["totp"]
            == MfaProviderUsage {
                allow_enrollment: false,
                allow_authentication: true,
            }
    );
    ensure!(
        config.provider_usage["external_device"]
            == MfaProviderUsage {
                allow_enrollment: true,
                allow_authentication: false,
            }
    );
    ensure!(config.provider_usage["future_device"] == MfaProviderUsage::default());
    ensure!(ConsoleMfaConfig::default().provider_usage.is_empty());
    ensure!(
        serde_json::from_value::<ConsoleMfaConfig>(serde_json::to_value(&config)?)?.provider_usage
            == config.provider_usage
    );
    for invalid in [
        serde_json::json!({"provider_usage": {"totp": {"allow_enrolment": false}}}),
        serde_json::json!({"provider_usage": {"totp": {"allow_enrollment": 0}}}),
        serde_json::json!({"provider_usage": {"totp": {"allow_authentication": null}}}),
        serde_json::json!({"provider_usage": {"totp": false}}),
    ] {
        ensure!(serde_json::from_value::<ConsoleMfaConfig>(invalid).is_err());
    }
    Ok(())
}

#[test]
fn factor_availability_has_only_the_three_host_dispatch_states() -> anyhow::Result<()> {
    for (state, value) in [
        (
            FactorAvailability::ProviderNotInstalled,
            "provider_not_installed",
        ),
        (
            FactorAvailability::AuthenticationDisabled,
            "authentication_disabled",
        ),
        (FactorAvailability::Available, "available"),
    ] {
        ensure!(serde_json::to_value(state)? == value);
        ensure!(serde_json::from_value::<FactorAvailability>(Value::from(value))? == state);
    }
    for invalid in [Value::Bool(true), Value::Null, Value::from("installed")] {
        ensure!(serde_json::from_value::<FactorAvailability>(invalid).is_err());
    }
    let old = serde_json::json!({
        "factor_id": "credential",
        "provider_id": "totp",
        "label": "Phone",
        "created_at": 1,
        "last_used_at": null,
        "available": true
    });
    ensure!(serde_json::from_value::<FactorSummary>(old).is_err());
    Ok(())
}

struct UnavailableProvider;

impl MfaProvider for UnavailableProvider {
    fn descriptor(&self) -> MfaProviderDescriptor {
        MfaProviderDescriptor {
            provider_id: "unavailable".into(),
            label: "Unavailable provider".into(),
            enrollment: None,
            authentication: MfaAuthenticationDescriptor {
                proof_schema: None,
                interaction: Some(MfaInteractionDescriptor {
                    challenge_schema: Value::Bool(true),
                }),
            },
        }
    }
}

fn context(purpose: MfaPurpose) -> MfaContext<'static> {
    MfaContext {
        authority_id: "local",
        username: "alice",
        account_id: "account-alice",
        factor_id: "factor-phone",
        label: "Phone",
        purpose,
        issuer: "Console",
        now_ms: 1_000,
    }
}

fn interaction() -> MfaInteractionContext<'static> {
    MfaInteractionContext {
        factor: context(MfaPurpose::Login),
        ceremony_id: "ceremony",
        round: 1,
        expires_at: 31_000,
    }
}

fn enrollment() -> MfaEnrollmentContext<'static> {
    MfaEnrollmentContext {
        factor: context(MfaPurpose::Enrollment),
        ceremony_id: "factor-phone",
        round: 1,
        expires_at: 31_000,
    }
}

#[tokio::test]
async fn unimplemented_provider_operations_fail_closed_without_fallback() {
    let provider = UnavailableProvider;
    let value = Value::Null;
    assert!(matches!(
        provider.begin_enrollment(enrollment(), None).await,
        Err(MfaProviderError::Unavailable)
    ));
    assert!(matches!(
        provider
            .continue_enrollment(
                enrollment(),
                &value,
                &MfaInteractionInput::Response {
                    response: value.clone()
                },
            )
            .await,
        Err(MfaProviderError::Unavailable)
    ));
    assert!(matches!(
        provider
            .verify_proof(context(MfaPurpose::Login), &value, &value)
            .await,
        Err(MfaProviderError::Unavailable)
    ));
    assert!(matches!(
        provider.begin_authentication(interaction(), &value).await,
        Err(MfaProviderError::Unavailable)
    ));
    assert!(matches!(
        provider
            .continue_authentication(interaction(), &value, &value, &MfaInteractionInput::Poll {})
            .await,
        Err(MfaProviderError::Unavailable)
    ));
}

#[test]
fn interaction_messages_are_tagged_and_keep_secret_payloads_out_of_debug() -> anyhow::Result<()> {
    let secret = "private-factor-material";
    let value = Value::String(secret.into());
    let response = MfaInteractionInput::Response {
        response: value.clone(),
    };
    ensure!(
        serde_json::to_value(&response)?
            == serde_json::json!({"kind":"response","response":secret})
    );
    ensure!(
        serde_json::to_value(MfaInteractionInput::Poll {})? == serde_json::json!({"kind":"poll"})
    );
    for invalid in [
        serde_json::json!({"kind":"poll","response":secret}),
        serde_json::json!({"kind":"response"}),
        serde_json::json!({"kind":"response","response":secret,"factor_id":"other"}),
    ] {
        ensure!(
            serde_json::from_value::<MfaInteractionInput>(invalid.clone()).is_err(),
            "accepted invalid interaction: {invalid}"
        );
        ensure!(
            serde_json::from_value::<crate::AuthenticationInput>(invalid.clone()).is_err(),
            "accepted invalid authentication input: {invalid}"
        );
    }
    // A provider may explicitly accept null, but omission is not a response.
    let null_response = serde_json::json!({"kind":"response","response":null});
    ensure!(serde_json::from_value::<MfaInteractionInput>(null_response.clone()).is_ok());
    ensure!(serde_json::from_value::<crate::AuthenticationInput>(null_response).is_ok());
    ensure!(
        serde_json::from_value::<MfaProof>(
            serde_json::json!({"kind":"factor","factor_id":"factor"})
        )
        .is_err()
    );
    ensure!(
        serde_json::from_value::<MfaRequest>(
            serde_json::json!({"operation":"continue","challenge_id":"pending"})
        )
        .is_err()
    );
    let debug = [
        format!("{response:?}"),
        format!(
            "{:?}",
            MfaEnrollmentStep::Challenge {
                setup: value.clone(),
                response_schema: Value::Bool(true),
                private_state: value.clone()
            }
        ),
        format!(
            "{:?}",
            MfaInteractionStep::Challenge {
                private_state: value.clone(),
                response_schema: Value::Bool(true),
                challenge: value.clone()
            }
        ),
        format!(
            "{:?}",
            MfaInteractionStep::Pending {
                private_state: value.clone(),
                status: value.clone(),
                retry_after_ms: 500
            }
        ),
        format!(
            "{:?}",
            MfaInteractionStep::Verified {
                next_verifier: value
            }
        ),
    ];
    ensure!(debug.iter().all(|output| !output.contains(secret)));
    Ok(())
}
