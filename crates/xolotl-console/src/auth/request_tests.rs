//! Strict Console request envelopes remain independent of credential verification.

use super::*;
use crate::{credentials::CredentialOperation, mfa::MfaRequest};
use anyhow::ensure;
use serde::de::DeserializeOwned;
use serde_json::{Value as JsonValue, json};

type RoundTrip = fn(JsonValue) -> Result<JsonValue, serde_json::Error>;

fn round_trip<T: DeserializeOwned + Serialize>(
    value: JsonValue,
) -> Result<JsonValue, serde_json::Error> {
    serde_json::to_value(serde_json::from_value::<T>(value)?)
}

#[test]
fn empty_credential_operations_reject_unrecognized_conditions() -> anyhow::Result<()> {
    let cases: [(&str, JsonValue, RoundTrip); 5] = [
        (
            "factor status",
            json!({"operation":"status"}),
            round_trip::<MfaRequest>,
        ),
        (
            "recovery-code regeneration",
            json!({"operation":"regenerate_recovery_codes"}),
            round_trip::<MfaRequest>,
        ),
        (
            "credential status",
            json!({"action":"status"}),
            round_trip::<CredentialOperation>,
        ),
        (
            "password disable",
            json!({"action":"disable_password"}),
            round_trip::<CredentialOperation>,
        ),
        (
            "second-factor reset",
            json!({"action":"reset_second_factors"}),
            round_trip::<CredentialOperation>,
        ),
    ];
    for (name, canonical, decode) in cases {
        ensure!(
            decode(canonical.clone())? == canonical,
            "changed canonical {name} message"
        );
        for (key, value) in [
            ("dry_run", json!(true)),
            ("username", json!("another-account")),
            ("proof", json!("unrecognized-condition")),
        ] {
            let mut extra = canonical.clone();
            extra[key] = value;
            ensure!(decode(extra).is_err(), "{name} accepted unrecognized {key}");
        }
    }
    Ok(())
}

#[test]
fn public_key_and_passkey_requests_reject_unknown_console_envelope_fields() -> anyhow::Result<()> {
    // These bytes need only satisfy the browser DTO. Cryptographic verification
    // remains the WebAuthn service's job, outside request-envelope decoding.
    let registration = json!({
        "id":"AQID", "rawId":"AQID", "type":"public-key", "clientExtensionResults":{},
        "response":{"attestationObject":"AQID", "clientDataJSON":"AQID"},
    });
    let assertion = json!({
        "id":"AQID", "rawId":"AQID", "type":"public-key", "clientExtensionResults":{},
        "response":{"authenticatorData":"AQID", "clientDataJSON":"AQID", "signature":"AQID"},
    });
    let cases: [(&str, JsonValue, RoundTrip); 5] = [
        (
            "key challenge",
            json!({"username":"alice","origin":"https://console.example"}),
            round_trip::<KeyChallengeRequest>,
        ),
        (
            "passkey registration begin",
            json!({"label":"Security key"}),
            round_trip::<PasskeyRegisterBeginRequest>,
        ),
        (
            "passkey registration finish",
            json!({"challenge_id":"challenge","credential":registration}),
            round_trip::<PasskeyRegisterFinishRequest>,
        ),
        (
            "passkey login begin",
            json!({"username":"alice"}),
            round_trip::<PasskeyLoginBeginRequest>,
        ),
        (
            "passkey login finish",
            json!({"username":"alice","challenge_id":"challenge","credential":assertion}),
            round_trip::<PasskeyLoginFinishRequest>,
        ),
    ];
    for (name, canonical, decode) in cases {
        let encoded = decode(canonical.clone())?;
        ensure!(decode(encoded).is_ok(), "{name} does not round-trip");
        for (key, value) in [("dry_run", json!(true)), ("sid", json!("another-session"))] {
            let mut extra = canonical.clone();
            extra[key] = value;
            ensure!(decode(extra).is_err(), "{name} accepted unrecognized {key}");
        }
    }
    Ok(())
}
