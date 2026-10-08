use aws_lc_rs::signature::{KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub struct PqcSigningKey(PqdsaKeyPair);

impl PqcSigningKey {
    #[expect(
        clippy::expect_used,
        reason = "test fixture cannot continue without a signing key"
    )]
    pub fn generate() -> Self {
        Self(PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("test ML-DSA key generation"))
    }

    pub fn descriptor(&self) -> String {
        format!(
            "ml-dsa-65:{}",
            URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref())
        )
    }

    #[expect(
        clippy::expect_used,
        reason = "test fixture cannot continue without a signature"
    )]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
        let len = self
            .0
            .sign(message, &mut signature)
            .expect("test ML-DSA signature");
        signature.truncate(len);
        signature
    }
}
