use super::*;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::Url;

/// RFC 6238 HMAC digest, serialized as `SHA1`, `SHA256`, or `SHA512`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 for an explicitly configured compatibility profile.
    Sha1,
    /// HMAC-SHA-256.
    #[default]
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// Parameters for newly enrolled TOTP factors. Each verifier persists its own
/// parameters so changing host defaults does not reinterpret existing secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TotpConfig {
    /// Digest used to derive each code; defaults to SHA-256.
    pub algorithm: TotpAlgorithm,
    /// Decimal code length, either 6 (default) or 8.
    pub digits: u8,
    /// Time-step duration in seconds, from 15 through 120; defaults to 30.
    pub period_seconds: u32,
    /// Accepted steps before and after the current step, from 0 through 2; defaults to 1.
    pub clock_skew_steps: u8,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha256,
            digits: 6,
            period_seconds: 30,
            clock_skew_steps: 1,
        }
    }
}

impl TotpConfig {
    pub(crate) fn valid(&self) -> bool {
        matches!(self.digits, 6 | 8)
            && (15..=120).contains(&self.period_seconds)
            && self.clock_skew_steps <= 2
    }
}

/// RFC 6238 provider with authenticator-compatible Base32 setup and otpauth URI.
pub struct TotpProvider(pub TotpConfig);

#[derive(Serialize, Deserialize)]
struct Verifier {
    secret: String,
    config: TotpConfig,
    last_step: Option<u64>,
}

impl MfaProvider for TotpProvider {
    fn descriptor(&self) -> MfaProviderDescriptor {
        MfaProviderDescriptor {
            provider_id: "totp".into(),
            label: "Authenticator app (TOTP)".into(),
            enrollment: Some(MfaEnrollmentDescriptor {
                begin_schema: None,
                setup_schema: serde_json::json!({"type":"object","required":["secret","otpauth_uri","algorithm","digits","period_seconds"]}),
                pending_schema: None,
            }),
            authentication: MfaAuthenticationDescriptor {
                proof_schema: Some(code_schema()),
                interaction: None,
            },
        }
    }

    fn begin_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        _input: Option<&'a serde_json::Value>,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            if !self.0.valid() {
                return Err(MfaProviderError::InvalidState);
            }
            let len = match self.0.algorithm {
                TotpAlgorithm::Sha1 => 20,
                TotpAlgorithm::Sha256 => 32,
                TotpAlgorithm::Sha512 => 64,
            };
            let mut secret = vec![0; len];
            getrandom::fill(&mut secret).map_err(|_error| MfaProviderError::Unavailable)?;
            let secret = BASE32_NOPAD.encode(&secret);
            let algorithm = match self.0.algorithm {
                TotpAlgorithm::Sha1 => "SHA1",
                TotpAlgorithm::Sha256 => "SHA256",
                TotpAlgorithm::Sha512 => "SHA512",
            };
            let mut uri =
                Url::parse("otpauth://totp/").map_err(|_error| MfaProviderError::InvalidState)?;
            uri.path_segments_mut()
                .map_err(|_error| MfaProviderError::InvalidState)?
                .clear()
                .push(&format!(
                    "{}:{} ({})",
                    context.factor.issuer, context.factor.username, context.factor.label
                ));
            uri.query_pairs_mut()
                .append_pair("secret", &secret)
                .append_pair("issuer", context.factor.issuer)
                .append_pair("algorithm", algorithm)
                .append_pair("digits", &self.0.digits.to_string())
                .append_pair("period", &self.0.period_seconds.to_string());
            let setup = serde_json::json!({"secret":secret,"otpauth_uri":uri.as_str(),"algorithm":algorithm,"digits":self.0.digits,"period_seconds":self.0.period_seconds});
            let verifier = serde_json::to_value(Verifier {
                secret,
                config: self.0.clone(),
                last_step: None,
            })
            .map_err(|_error| MfaProviderError::InvalidState)?;
            Ok(MfaEnrollmentStep::Challenge {
                setup,
                private_state: verifier,
                response_schema: code_schema(),
            })
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        private_state: &'a Value,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            let MfaInteractionInput::Response { response } = input else {
                return Err(MfaProviderError::InvalidInput);
            };
            let verifier = verify_code(context.factor.now_ms, private_state, response)?;
            Ok(MfaEnrollmentStep::Verified { verifier })
        })
    }

    fn verify_proof<'a>(
        &'a self,
        context: MfaContext<'a>,
        verifier: &'a Value,
        proof: &'a Value,
    ) -> MfaFuture<'a, Value> {
        Box::pin(async move { verify_code(context.now_ms, verifier, proof) })
    }
}

fn code_schema() -> Value {
    serde_json::json!({"type":"object","required":["code"],"additionalProperties":false,"properties":{"code":{"type":"string","pattern":"^[0-9]{6}([0-9]{2})?$"}}})
}

fn verify_code(now_ms: i64, verifier: &Value, proof: &Value) -> Result<Value, MfaProviderError> {
    let mut verifier: Verifier = serde_json::from_value(verifier.clone())
        .map_err(|_error| MfaProviderError::InvalidState)?;
    if !verifier.config.valid() || now_ms < 0 {
        return Err(MfaProviderError::InvalidState);
    }
    let code = proof
        .as_object()
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get("code"))
        .and_then(Value::as_str)
        .ok_or(MfaProviderError::InvalidProof)?;
    if code.len() != usize::from(verifier.config.digits)
        || !code.bytes().all(|v| v.is_ascii_digit())
    {
        return Err(MfaProviderError::InvalidProof);
    }
    let secret = BASE32_NOPAD
        .decode(verifier.secret.as_bytes())
        .map_err(|_error| MfaProviderError::InvalidState)?;
    if !(20..=64).contains(&secret.len()) {
        return Err(MfaProviderError::InvalidState);
    }
    let current = now_ms as u64 / 1000 / u64::from(verifier.config.period_seconds);
    let skew = u64::from(verifier.config.clock_skew_steps);
    for step in current.saturating_sub(skew)..=current.saturating_add(skew) {
        if verifier.last_step.is_some_and(|last| step <= last) {
            continue;
        }
        if code
            .as_bytes()
            .ct_eq(code_at(&secret, step, &verifier.config)?.as_bytes())
            .unwrap_u8()
            == 1
        {
            verifier.last_step = Some(step);
            return serde_json::to_value(verifier).map_err(|_error| MfaProviderError::InvalidState);
        }
    }
    Err(MfaProviderError::InvalidProof)
}

pub(crate) fn code_at(
    secret: &[u8],
    step: u64,
    config: &TotpConfig,
) -> Result<String, MfaProviderError> {
    macro_rules! digest {
        ($algorithm:ty) => {{
            let mut mac = Hmac::<$algorithm>::new_from_slice(secret)
                .map_err(|_error| MfaProviderError::InvalidState)?;
            mac.update(&step.to_be_bytes());
            mac.finalize().into_bytes().to_vec()
        }};
    }
    let hash = match config.algorithm {
        TotpAlgorithm::Sha1 => digest!(Sha1),
        TotpAlgorithm::Sha256 => digest!(Sha256),
        TotpAlgorithm::Sha512 => digest!(Sha512),
    };
    let offset = usize::from(hash[hash.len() - 1] & 15);
    let binary = u32::from_be_bytes([
        hash[offset] & 127,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    Ok(format!(
        "{:0width$}",
        binary % 10u32.pow(u32::from(config.digits)),
        width = usize::from(config.digits)
    ))
}

#[cfg(test)]
mod tests;
