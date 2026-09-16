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
fn console_ed25519_v1_accepts_a_fixed_signature_with_canonical_base64() -> anyhow::Result<()> {
    // Independently signed by Node/OpenSSL with the Ed25519 seed [7; 32].
    const DESCRIPTOR: &str = "ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
    const SIGNATURE: &str = concat!(
        "YXl6-fdCQqBP-tIKALyAameee61-iT13gdjIMB3lVsjHsSLpVRsHD6KhLhvnj4ZM",
        "zza9LulrKsel4b7HJAKlDQ",
    );
    let transcript = key_login_transcript(
        "alice",
        "challenge-v1",
        "nonce-v1",
        "https://console.example",
    );
    ensure!(
        transcript
            == "xolotl-console-ed25519-v1\nalice\nchallenge-v1\nnonce-v1\nhttps://console.example"
    );
    let descriptors = [DESCRIPTOR.to_string()];
    ensure!(verify_key_login(
        &descriptors,
        Some(DESCRIPTOR),
        SIGNATURE,
        &transcript,
    )?);
    let other_origin =
        key_login_transcript("alice", "challenge-v1", "nonce-v1", "https://other.example");
    ensure!(!verify_key_login(
        &descriptors,
        Some(DESCRIPTOR),
        SIGNATURE,
        &other_origin,
    )?);
    ensure!(!verify_key_login(
        &descriptors,
        Some("ed25519:another-key"),
        SIGNATURE,
        &transcript,
    )?);
    // R preserves Q's data bits but sets a nonzero unused Base64 tail bit.
    for invalid in [
        format!("{SIGNATURE}="),
        format!("{}R", &SIGNATURE[..SIGNATURE.len() - 1]),
    ] {
        ensure!(matches!(
            verify_key_login(&descriptors, None, &invalid, &transcript),
            Err(AuthError::InvalidCredentials)
        ));
    }
    Ok(())
}
