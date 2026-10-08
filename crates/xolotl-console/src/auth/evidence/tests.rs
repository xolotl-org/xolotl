use super::*;
use anyhow::ensure;

fn password() -> PrimaryAuthentication {
    PrimaryAuthentication::Password { verified_at: 17 }
}

#[test]
fn retained_proof_kinds_and_references_have_one_canonical_shape() -> anyhow::Result<()> {
    let key = crate::auth::test_key::TestSigningKey::generate();
    let primaries = [
        password(),
        PrimaryAuthentication::PublicKey {
            credential_key: key.descriptor(),
            verified_at: 19,
        },
        PrimaryAuthentication::PasskeyUv {
            credential_id: URL_SAFE_NO_PAD.encode([4, 8, 12]),
            verified_at: 23,
        },
    ];
    for primary in primaries {
        for secondary in [
            None,
            Some(SecondaryAuthentication::Factor {
                factor_id: format!("t{}", "a".repeat(24)),
                provider_id: "totp".into(),
                verified_at: 29,
            }),
            Some(SecondaryAuthentication::RecoveryCode { verified_at: 31 }),
        ] {
            let evidence = AuthenticationEvidence {
                primary: primary.clone(),
                secondary,
            };
            let value = evidence.to_value();
            ensure!(AuthenticationEvidence::from_value(&value)? == evidence);
            let json = serde_json::to_value(&evidence)?;
            ensure!(serde_json::to_value(value)? == json);
            ensure!(serde_json::from_value::<AuthenticationEvidence>(json)? == evidence);
            // Decoding historical proofs never requires a live credential directory.
        }
    }
    Ok(())
}

#[test]
fn evidence_rejects_missing_unknown_and_impossible_proof_shapes() -> anyhow::Result<()> {
    let malformed = [
        serde_json::json!({"primary":{"method":"password","verified_at":1}}),
        serde_json::json!({"primary":{"method":"session","sid":"owner","verified_at":1},"secondary":null}),
        serde_json::json!({"primary":{"method":"password","verified_at":-1},"secondary":null}),
        serde_json::json!({"primary":{"method":"password","verified_at":1,"credential_id":"invented"},"secondary":null}),
        serde_json::json!({"primary":{"method":"passkey_uv","verified_at":1,"credential_id":"BA=="},"secondary":null}),
        serde_json::json!({"primary":{"method":"passkey_uv","verified_at":1,"credential_id":"BB"},"secondary":null}),
        serde_json::json!({"primary":{"method":"passkey_uv","verified_at":1,"credential_id":""},"secondary":null}),
        serde_json::json!({"primary":{"method":"passkey_uv","verified_at":1,"credential_id":"BA","user_verified":false},"secondary":null}),
        serde_json::json!({"primary":{"method":"password","verified_at":1},"secondary":{"method":"recovery_code","verified_at":2,"digest":"secret"}}),
        serde_json::json!({"primary":{"method":"password","verified_at":1},"secondary":{"method":"factor","verified_at":2,"factor_id":"totp","provider_id":"totp"}}),
        serde_json::json!({"primary":{"method":"password","verified_at":1},"secondary":{"method":"factor","verified_at":2,"factor_id":format!("t{}", "a".repeat(24)),"provider_id":"bad/provider"}}),
        serde_json::json!({"primary":{"method":"password","verified_at":1},"secondary":null,"mfa_level":2}),
    ];
    for json in malformed {
        let value = serde_json::from_value::<Value>(json.clone())?;
        ensure!(
            AuthenticationEvidence::from_value(&value).is_err(),
            "accepted {json}"
        );
    }
    ensure!(
        serde_json::from_value::<AuthenticationEvidence>(serde_json::json!({
            "primary":{"method":"password","verified_at":1}
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn admission_and_recency_are_derived_from_proofs_without_rewriting_them() {
    let mut evidence = AuthenticationEvidence {
        primary: password(),
        secondary: None,
    };
    assert_eq!(evidence.mfa_level(), 1);
    assert_eq!(evidence.authenticated_at(), Some(17));
    evidence.secondary = Some(SecondaryAuthentication::RecoveryCode { verified_at: 11 });
    assert_eq!(evidence.mfa_level(), 2);
    assert_eq!(evidence.authenticated_at(), Some(17));
    evidence.secondary = Some(SecondaryAuthentication::RecoveryCode { verified_at: 29 });
    assert_eq!(evidence.authenticated_at(), Some(29));
    assert_eq!(evidence.primary, password());
    evidence.primary = PrimaryAuthentication::PasskeyUv {
        credential_id: URL_SAFE_NO_PAD.encode([1, 2, 3]),
        verified_at: 41,
    };
    evidence.secondary = None;
    assert_eq!(evidence.mfa_level(), 2);
    assert_eq!(evidence.authenticated_at(), Some(41));
}
