use super::*;
use anyhow::ensure;

#[test]
fn argon2id_reference_phc_verifies() {
    // PHC-winner reference fixture shipped in argon2 0.5.3's PHC tests.
    const PHC: &str = concat!(
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$",
        "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
    );
    assert!(verify_password(PHC, "password"));
    assert!(!verify_password(PHC, "sassword"));
    assert!(!verify_password("invalid PHC", "password"));
}

#[test]
fn password_hash_encoding_preserves_parameters_and_raw_salt() -> anyhow::Result<()> {
    // OpenSSL ARGON2ID: v=19, m=256, t=1, p=1, output=32, salt=[1; 16].
    const EXPECTED: &str = concat!(
        "$argon2id$v=19$m=256,t=1,p=1$AQEBAQEBAQEBAQEBAQEBAQ$",
        "7YeDiY5sL+xQaXvCjFX1m2n7z0Q2zPROJtHuJvbxP4Y",
    );
    ensure!(hash_password_with_salt("strong-root-password-9qL", &[1; 16])? == EXPECTED);
    Ok(())
}

#[test]
fn console_ml_dsa_65_v1_accepts_a_signature_and_rejects_other_transcripts() -> anyhow::Result<()> {
    let key = super::test_key::TestSigningKey::generate();
    let descriptor = key.descriptor();
    let transcript = key_login_transcript(
        "alice",
        "challenge-v1",
        "nonce-v1",
        "https://console.example",
    );
    ensure!(
        transcript
            == "xolotl-console-ml-dsa-65-v1\nalice\nchallenge-v1\nnonce-v1\nhttps://console.example"
    );
    let signature = URL_SAFE_NO_PAD.encode(key.sign(transcript.as_bytes()));
    let descriptors = [descriptor.clone()];
    ensure!(verify_key_login(&descriptors, &descriptor, &signature, &transcript,)?.is_some());
    let other_origin =
        key_login_transcript("alice", "challenge-v1", "nonce-v1", "https://other.example");
    ensure!(verify_key_login(&descriptors, &descriptor, &signature, &other_origin,)?.is_none());
    ensure!(
        verify_key_login(
            &descriptors,
            "ml-dsa-65:another-key",
            &signature,
            &transcript,
        )?
        .is_none()
    );
    for invalid in [format!("{signature}="), format!("{signature}A")] {
        ensure!(matches!(
            verify_key_login(&descriptors, &descriptor, &invalid, &transcript),
            Err(AuthError::InvalidCredentials)
        ));
    }
    ensure!(matches!(
        credentials::canonical_public_key("ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"),
        Err(AuthError::InvalidCredentialRequest)
    ));
    Ok(())
}
