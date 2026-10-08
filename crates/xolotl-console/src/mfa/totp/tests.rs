use super::*;
use anyhow::ensure;

#[test]
fn rfc6238_vectors_cover_all_algorithms_and_large_timestamps() -> anyhow::Result<()> {
    let seeds = [
        b"12345678901234567890".as_slice(),
        b"12345678901234567890123456789012".as_slice(),
        b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
    ];
    for (time, expected) in [
        (59, ["94287082", "46119246", "90693936"]),
        (1111111109, ["07081804", "68084774", "25091201"]),
        (1111111111, ["14050471", "67062674", "99943326"]),
        (1234567890, ["89005924", "91819424", "93441116"]),
        (2000000000, ["69279037", "90698825", "38618901"]),
        (20000000000, ["65353130", "77737706", "47863826"]),
    ] {
        for (index, algorithm) in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ]
        .into_iter()
        .enumerate()
        {
            ensure!(
                code_at(
                    seeds[index],
                    time / 30,
                    &TotpConfig {
                        algorithm,
                        digits: 8,
                        ..Default::default()
                    }
                )? == expected[index]
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn consumed_steps_and_codes_outside_the_window_are_rejected() -> anyhow::Result<()> {
    let provider = TotpProvider(TotpConfig::default());
    let context = |purpose| MfaContext {
        authority_id: "local",
        username: "alice",
        account_id: "account-alice",
        factor_id: "factor-phone",
        label: "Phone",
        purpose,
        issuer: "Xolotl",
        now_ms: 90_000,
    };
    let enrollment = provider
        .begin_enrollment(
            MfaEnrollmentContext {
                factor: context(MfaPurpose::Enrollment),
                ceremony_id: "factor-phone",
                round: 1,
                expires_at: 300_000,
            },
            None,
        )
        .await?;
    let MfaEnrollmentStep::Challenge { private_state, .. } = enrollment else {
        anyhow::bail!("TOTP enrollment must produce a setup challenge");
    };
    let verifier: Verifier = serde_json::from_value(private_state.clone())?;
    let secret = BASE32_NOPAD.decode(verifier.secret.as_bytes())?;
    let proof = serde_json::json!({"code":code_at(&secret, 3, &verifier.config)?});
    let MfaEnrollmentStep::Verified { verifier: consumed } = provider
        .continue_enrollment(
            MfaEnrollmentContext {
                factor: context(MfaPurpose::Enrollment),
                ceremony_id: "factor-phone",
                round: 2,
                expires_at: 300_000,
            },
            &private_state,
            &MfaInteractionInput::Response {
                response: proof.clone(),
            },
        )
        .await?
    else {
        anyhow::bail!("TOTP enrollment must finish");
    };
    ensure!(matches!(
        provider
            .verify_proof(context(MfaPurpose::Login), &consumed, &proof)
            .await,
        Err(MfaProviderError::InvalidProof)
    ));
    for step in [0, 1, 5, 6] {
        let proof = serde_json::json!({"code":code_at(&secret, step, &verifier.config)?});
        ensure!(matches!(
            provider
                .verify_proof(context(MfaPurpose::Login), &private_state, &proof)
                .await,
            Err(MfaProviderError::InvalidProof)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn setup_encodes_issuer_and_account_and_verifiers_reject_weak_secrets() -> anyhow::Result<()>
{
    let provider = TotpProvider(TotpConfig::default());
    let context = || MfaContext {
        authority_id: "local",
        username: "alice+ops@example.org",
        account_id: "account-alice",
        factor_id: "factor-phone",
        label: "Phone / 备用 & travel",
        purpose: MfaPurpose::Enrollment,
        issuer: "Console / 研发 & Ops",
        now_ms: 90_000,
    };
    let MfaEnrollmentStep::Challenge {
        mut private_state,
        setup,
        ..
    } = provider
        .begin_enrollment(
            MfaEnrollmentContext {
                factor: context(),
                ceremony_id: "factor-phone",
                round: 1,
                expires_at: 300_000,
            },
            None,
        )
        .await?
    else {
        anyhow::bail!("TOTP enrollment must produce a setup challenge");
    };
    let uri = Url::parse(
        setup["otpauth_uri"]
            .as_str()
            .ok_or(MfaProviderError::InvalidState)?,
    )?;
    ensure!(uri.scheme() == "otpauth" && uri.host_str() == Some("totp"));
    let pairs: std::collections::BTreeMap<_, _> = uri.query_pairs().collect();
    ensure!(pairs.get("issuer").map(|v| v.as_ref()) == Some(context().issuer));
    ensure!(pairs.get("secret").map(|v| v.as_ref()) == setup["secret"].as_str());
    ensure!(pairs.get("algorithm").map(|v| v.as_ref()) == Some("SHA256"));
    ensure!(
        BASE32_NOPAD
            .decode(setup["secret"].as_str().unwrap_or_default().as_bytes())?
            .len()
            == 32
    );
    ensure!(uri.path().contains("Phone%20%2F%20") && uri.path().contains("alice+ops@example.org"));
    ensure!(
        uri.path_segments()
            .ok_or(MfaProviderError::InvalidState)?
            .count()
            == 1
    );
    for secret in ["", "AA", "not-base32"] {
        private_state["secret"] = serde_json::json!(secret);
        ensure!(matches!(
            provider
                .continue_enrollment(
                    MfaEnrollmentContext {
                        factor: context(),
                        ceremony_id: "factor-phone",
                        round: 2,
                        expires_at: 300_000
                    },
                    &private_state,
                    &MfaInteractionInput::Response {
                        response: serde_json::json!({"code":"123456"})
                    }
                )
                .await,
            Err(MfaProviderError::InvalidState)
        ));
    }
    Ok(())
}
