//! Installation is host policy, independent of retained factor parameters.

use super::*;
use crate::mfa::{
    ConsoleMfaConfig, MfaAuthenticationDescriptor, MfaEnrollmentDescriptor,
    MfaInteractionDescriptor, TotpConfig,
};

struct DeclaredProvider(MfaProviderDescriptor);

impl MfaProvider for DeclaredProvider {
    fn descriptor(&self) -> MfaProviderDescriptor {
        self.0.clone()
    }
}

fn descriptor(id: impl Into<String>) -> MfaProviderDescriptor {
    MfaProviderDescriptor {
        provider_id: id.into(),
        label: "Custom factor".into(),
        enrollment: Some(MfaEnrollmentDescriptor {
            begin_schema: None,
            setup_schema: serde_json::json!(true),
            pending_schema: None,
        }),
        authentication: MfaAuthenticationDescriptor {
            proof_schema: Some(serde_json::json!({"type": "string"})),
            interaction: None,
        },
    }
}

fn extension(id: impl Into<String>) -> Arc<dyn MfaProvider> {
    Arc::new(DeclaredProvider(descriptor(id)))
}

fn config(install_totp: bool, providers: Vec<Arc<dyn MfaProvider>>) -> ConsoleAuthConfig {
    ConsoleAuthConfig {
        mfa: ConsoleMfaConfig {
            install_totp,
            providers,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn default_empty_and_custom_only_installations_are_explicit() -> anyhow::Result<()> {
    let defaults = ConsoleAuthConfig::default();
    ensure!(defaults.mfa.install_totp);
    let installed = super::super::providers(&defaults)?;
    ensure!(installed.keys().map(String::as_str).collect::<Vec<_>>() == ["totp"]);
    ensure!(super::super::providers(&config(false, Vec::new()))?.is_empty());
    let installed = super::super::providers(&config(false, vec![extension("custom")]))?;
    ensure!(installed.keys().map(String::as_str).collect::<Vec<_>>() == ["custom"]);
    Ok(())
}

#[test]
fn usage_for_uninstalled_providers_is_validated_without_installing_them() -> anyhow::Result<()> {
    let mut configuration = config(false, Vec::new());
    configuration.mfa.provider_usage.insert(
        "totp".into(),
        MfaProviderUsage {
            allow_enrollment: false,
            allow_authentication: true,
        },
    );
    configuration
        .mfa
        .provider_usage
        .insert("future_provider".into(), MfaProviderUsage::default());
    ensure!(super::super::providers(&configuration)?.is_empty());
    configuration.mfa.install_totp = true;
    let installed = super::super::providers(&configuration)?;
    ensure!(installed.len() == 1);
    ensure!(installed["totp"].usage == configuration.mfa.provider_usage["totp"]);
    for invalid_id in ["", "Upper", "bad.id", &"x".repeat(65)] {
        let mut invalid = configuration.clone();
        invalid
            .mfa
            .provider_usage
            .insert(invalid_id.into(), MfaProviderUsage::default());
        ensure!(super::super::providers(&invalid).is_err());
    }
    Ok(())
}

#[test]
fn installed_usage_and_capabilities_jointly_control_each_dispatch() -> anyhow::Result<()> {
    let mut auth = ConsoleAuth::new(config(false, Vec::new()))?;
    for enrollment_supported in [false, true] {
        for direct in [false, true] {
            for allow_enrollment in [false, true] {
                for allow_authentication in [false, true] {
                    let mut declaration = descriptor("custom");
                    if !enrollment_supported {
                        declaration.enrollment = None;
                    }
                    if !direct {
                        declaration.authentication.proof_schema = None;
                        declaration.authentication.interaction = Some(MfaInteractionDescriptor {
                            challenge_schema: JsonValue::Bool(true),
                        });
                    }
                    let mut configuration =
                        config(false, vec![Arc::new(DeclaredProvider(declaration.clone()))]);
                    let usage = MfaProviderUsage {
                        allow_enrollment,
                        allow_authentication,
                    };
                    configuration
                        .mfa
                        .provider_usage
                        .insert("custom".into(), usage);
                    auth.mfa_providers = super::super::providers(&configuration)?;
                    auth.config = configuration;
                    // Admission consumes the installed value, not a mutable
                    // configuration lookup or a new provider declaration.
                    auth.config.mfa.provider_usage.clear();
                    let catalog = auth.mfa_providers();
                    ensure!(catalog.len() == 1 && catalog[0].usage == usage);
                    ensure!(
                        serde_json::to_value(&catalog[0].descriptor)?
                            == serde_json::to_value(&declaration)?
                    );
                    for (operation, allowed, supported) in [
                        (
                            ProviderOperation::Enrollment,
                            allow_enrollment,
                            enrollment_supported,
                        ),
                        (ProviderOperation::Proof, allow_authentication, direct),
                        (
                            ProviderOperation::Interaction,
                            allow_authentication,
                            !direct,
                        ),
                    ] {
                        match auth.provider_for("custom", operation) {
                            Ok(provider) => {
                                ensure!(allowed && supported);
                                ensure!(provider.usage == usage);
                            }
                            Err(AuthError::MfaUsageDenied) => ensure!(!allowed),
                            Err(AuthError::MfaOperationUnavailable) => {
                                ensure!(allowed && !supported)
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    let factor = StoredFactor {
                        provider_id: "custom".into(),
                        label: "Device".into(),
                        created_at: 1,
                        last_used_at: None,
                        verifier: JsonValue::Null,
                    };
                    let expected = if allow_authentication {
                        FactorAvailability::Available
                    } else {
                        FactorAvailability::AuthenticationDisabled
                    };
                    ensure!(auth.factor_summary("factor", &factor).availability == expected);
                    let missing = StoredFactor {
                        provider_id: "missing".into(),
                        ..factor
                    };
                    ensure!(
                        auth.factor_summary("factor", &missing).availability
                            == FactorAvailability::ProviderNotInstalled
                    );
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn denied_usage_precedes_proof_validation_and_enrollment_dispatch() -> anyhow::Result<()> {
    let mut configuration = config(false, vec![extension("custom")]);
    configuration.mfa.provider_usage.insert(
        "custom".into(),
        MfaProviderUsage {
            allow_enrollment: false,
            allow_authentication: false,
        },
    );
    let auth = ConsoleAuth::new(configuration)?;
    let account_key = AccountKey::local("account");
    let oversized = JsonValue::String("x".repeat(MAX_PROOF_BYTES + 1));
    let verifier = JsonValue::Null;
    for response in [&oversized, &JsonValue::Null] {
        ensure!(matches!(
            auth.verify_factor_proof(
                auth.mfa_context("alice", &account_key, "factor", "Device", MfaPurpose::Login),
                "custom",
                &verifier,
                response,
            )
            .await,
            Err(AuthError::MfaUsageDenied)
        ));
    }
    ensure!(matches!(
        auth.provider_for("custom", ProviderOperation::Enrollment),
        Err(AuthError::MfaUsageDenied)
    ));
    Ok(())
}

#[test]
fn capacity_counts_only_actually_installed_providers() -> anyhow::Result<()> {
    for (install_totp, available) in [(false, 32), (true, 31)] {
        let mut config = config(
            install_totp,
            (0..available)
                .map(|index| extension(format!("factor_{index}")))
                .collect(),
        );
        let installed = super::super::providers(&config)?;
        ensure!(installed.len() == 32);
        ensure!(installed.contains_key("totp") == install_totp);
        config.mfa.providers.push(extension("overflow"));
        ensure!(super::super::providers(&config).is_err());
    }
    Ok(())
}

#[test]
fn duplicate_ids_reject_installation_and_disabled_totp_allows_an_explicit_implementation()
-> anyhow::Result<()> {
    for install_totp in [false, true] {
        ensure!(
            super::super::providers(&config(
                install_totp,
                vec![extension("same"), extension("same")],
            ))
            .is_err()
        );
    }
    let compatible: Arc<dyn MfaProvider> = Arc::new(TotpProvider(TotpConfig::default()));
    ensure!(super::super::providers(&config(true, vec![compatible.clone()])).is_err());
    let installed = super::super::providers(&config(false, vec![compatible]))?;
    ensure!(installed.keys().map(String::as_str).collect::<Vec<_>>() == ["totp"]);
    Ok(())
}

#[test]
fn uninstalled_builtin_parameters_do_not_reject_host_assembly() -> anyhow::Result<()> {
    let mut config = config(false, vec![extension("custom")]);
    config.mfa.totp = TotpConfig {
        digits: 0,
        period_seconds: 0,
        clock_skew_steps: u8::MAX,
        ..Default::default()
    };
    let auth = ConsoleAuth::new(config.clone())?;
    ensure!(auth.mfa_providers().len() == 1);
    ensure!(auth.mfa_providers()[0].descriptor.provider_id == "custom");
    config.mfa.install_totp = true;
    ensure!(ConsoleAuth::new(config).is_err());
    Ok(())
}

#[test]
fn invalid_descriptors_reject_the_installation_boundary() -> anyhow::Result<()> {
    let mut invalid = Vec::new();
    for id in ["", "Upper", "bad.id"] {
        invalid.push(descriptor(id));
    }
    invalid.push(descriptor("x".repeat(65)));
    for label in [
        String::new(),
        " ".into(),
        "control\n".into(),
        "x".repeat(129),
    ] {
        let mut candidate = descriptor("custom");
        candidate.label = label;
        invalid.push(candidate);
    }
    for schema in [
        JsonValue::Null,
        serde_json::json!(17),
        serde_json::json!([]),
        serde_json::json!("proof"),
    ] {
        let mut candidate = descriptor("custom");
        candidate.authentication.proof_schema = Some(schema);
        invalid.push(candidate);
    }
    let mut oversized = descriptor("custom");
    oversized.authentication.proof_schema =
        Some(serde_json::json!({"description": "x".repeat(MAX_PROOF_BYTES)}));
    invalid.push(oversized);
    for candidate in invalid {
        let config = config(false, vec![Arc::new(DeclaredProvider(candidate))]);
        ensure!(super::super::providers(&config).is_err());
    }
    // JSON Schema's boolean forms are valid declarations too.
    for schema in [true, false] {
        let mut candidate = descriptor("custom");
        candidate.authentication.proof_schema = Some(JsonValue::Bool(schema));
        ensure!(
            super::super::providers(&config(false, vec![Arc::new(DeclaredProvider(candidate))]))?
                .len()
                == 1
        );
    }
    Ok(())
}

#[test]
fn authentication_capabilities_are_explicit_and_independent_of_enrollment() -> anyhow::Result<()> {
    for enrollment in [false, true] {
        for (direct, interactive) in [(true, false), (false, true), (true, true), (false, false)] {
            let mut candidate = descriptor("custom");
            if !enrollment {
                candidate.enrollment = None;
            }
            if !direct {
                candidate.authentication.proof_schema = None;
            }
            candidate.authentication.interaction = interactive.then(|| MfaInteractionDescriptor {
                challenge_schema: serde_json::json!({"type":"string"}),
            });
            let installed = super::super::providers(&config(
                false,
                vec![Arc::new(DeclaredProvider(candidate.clone()))],
            ));
            if direct || interactive {
                let installed = installed?;
                ensure!(
                    serde_json::to_value(&installed["custom"].descriptor)?
                        == serde_json::to_value(&candidate)?
                );
            } else {
                ensure!(
                    installed.is_err(),
                    "enrollment alone cannot authenticate an active factor"
                );
            }
        }
    }
    Ok(())
}

fn descriptor_schemas(
    descriptor: &mut MfaProviderDescriptor,
) -> anyhow::Result<[&mut JsonValue; 5]> {
    let enrollment = descriptor
        .enrollment
        .as_mut()
        .context("enrollment schema")?;
    let begin = enrollment.begin_schema.as_mut().context("begin schema")?;
    let pending = enrollment
        .pending_schema
        .as_mut()
        .context("pending schema")?;
    let proof = descriptor
        .authentication
        .proof_schema
        .as_mut()
        .context("proof schema")?;
    let interaction = descriptor
        .authentication
        .interaction
        .as_mut()
        .context("interaction schemas")?;
    Ok([
        begin,
        &mut enrollment.setup_schema,
        pending,
        proof,
        &mut interaction.challenge_schema,
    ])
}

fn nested_schema(containers: usize) -> JsonValue {
    (0..containers).fold(
        JsonValue::Bool(true),
        |nested, _| serde_json::json!({"not":nested}),
    )
}

#[test]
fn every_descriptor_schema_is_bounded_and_validated_before_installation() -> anyhow::Result<()> {
    let mut complete = descriptor("custom");
    complete
        .enrollment
        .as_mut()
        .context("enrollment")?
        .begin_schema = Some(JsonValue::Bool(true));
    complete
        .enrollment
        .as_mut()
        .context("enrollment")?
        .pending_schema = Some(JsonValue::Bool(true));
    complete.authentication.interaction = Some(MfaInteractionDescriptor {
        challenge_schema: JsonValue::Bool(true),
    });
    for slot in 0..5 {
        for schema in [
            JsonValue::Null,
            serde_json::json!([]),
            nested_schema(MAX_JSON_DEPTH + 1),
            serde_json::json!({"description":"x".repeat(MAX_PROOF_BYTES)}),
        ] {
            let mut candidate = complete.clone();
            *descriptor_schemas(&mut candidate)?[slot] = schema;
            ensure!(
                super::super::providers(&config(
                    false,
                    vec![Arc::new(DeclaredProvider(candidate))],
                ))
                .is_err(),
                "invalid schema in operation slot {slot}"
            );
        }
        for schema in [JsonValue::Bool(false), nested_schema(MAX_JSON_DEPTH)] {
            let mut candidate = complete.clone();
            *descriptor_schemas(&mut candidate)?[slot] = schema;
            ensure!(
                super::super::providers(&config(
                    false,
                    vec![Arc::new(DeclaredProvider(candidate))],
                ))?
                .len()
                    == 1
            );
        }
    }
    // Array annotations count toward the same depth budget as object schemas.
    let mut candidate = complete;
    candidate.authentication.proof_schema = Some(serde_json::json!({
        "examples": (0..MAX_JSON_DEPTH).fold(JsonValue::Null, |nested, _| {
            serde_json::json!([nested])
        })
    }));
    ensure!(
        super::super::providers(&config(false, vec![Arc::new(DeclaredProvider(candidate))],))
            .is_err()
    );
    Ok(())
}

#[test]
fn json_limits_measure_encoded_bytes_and_all_container_shapes() {
    assert!(bounded_json(&JsonValue::String(
        "x".repeat(MAX_PROOF_BYTES - 2)
    )));
    assert!(!bounded_json(&JsonValue::String(
        "x".repeat(MAX_PROOF_BYTES - 1)
    )));
    // Escaping makes the wire representation larger than the raw UTF-8 string.
    assert!(!bounded_json(&JsonValue::String(
        "\n".repeat(MAX_PROOF_BYTES / 2)
    )));
    assert!(bounded_json(&nested_schema(MAX_JSON_DEPTH)));
    assert!(!bounded_json(&nested_schema(MAX_JSON_DEPTH + 1)));
    assert!(!bounded_json(&serde_json::json!(vec![
        false;
        MAX_PROOF_BYTES
    ])));
    assert!(!bounded_json(
        &serde_json::json!({"x".repeat(MAX_PROOF_BYTES):true})
    ));
}

#[test]
fn serialized_config_preserves_installation_policy_without_native_extensions() -> anyhow::Result<()>
{
    let defaulted: ConsoleMfaConfig = serde_json::from_value(serde_json::json!({}))?;
    ensure!(defaulted.install_totp && defaulted.providers.is_empty());
    ensure!(defaulted.authentication_ttl_ms == 120_000);
    ensure!(defaulted.max_authentication_steps == 16 && defaulted.min_poll_interval_ms == 500);
    let disabled: ConsoleMfaConfig =
        serde_json::from_value(serde_json::json!({"install_totp":false}))?;
    ensure!(!disabled.install_totp && disabled.providers.is_empty());
    for install_totp in [false, true] {
        let mut original = config(install_totp, vec![extension("native")]).mfa;
        original.authentication_ttl_ms = 90_000;
        original.max_authentication_steps = 8;
        original.min_poll_interval_ms = 750;
        let encoded = serde_json::to_value(&original)?;
        ensure!(encoded["install_totp"].as_bool() == Some(install_totp));
        ensure!(encoded.get("providers").is_none());
        let decoded: ConsoleMfaConfig = serde_json::from_value(encoded.clone())?;
        ensure!(decoded.install_totp == install_totp && decoded.providers.is_empty());
        ensure!(serde_json::to_value(decoded)? == encoded);
    }
    for invalid in [
        serde_json::json!({"install_totp":null}),
        serde_json::json!({"install_totp":"false"}),
        serde_json::json!({"install_topt":false}),
        serde_json::json!({"providers":[{"provider_id":"remote"}]}),
    ] {
        ensure!(serde_json::from_value::<ConsoleMfaConfig>(invalid).is_err());
    }
    Ok(())
}
