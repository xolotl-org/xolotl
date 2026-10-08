//! ML-DSA-65 signing fixture for Console authentication tests.

use aws_lc_rs::signature::{KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) struct TestSigningKey(PqdsaKeyPair);

impl TestSigningKey {
    #[expect(
        clippy::expect_used,
        reason = "test fixture cannot continue without a signing key"
    )]
    pub(super) fn generate() -> Self {
        Self(PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("test ML-DSA key generation"))
    }

    pub(super) fn descriptor(&self) -> String {
        format!(
            "ml-dsa-65:{}",
            URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref())
        )
    }

    #[expect(
        clippy::expect_used,
        reason = "test fixture cannot continue without a signature"
    )]
    pub(super) fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
        let len = self
            .0
            .sign(message, &mut signature)
            .expect("test ML-DSA signature");
        signature.truncate(len);
        signature
    }
}
