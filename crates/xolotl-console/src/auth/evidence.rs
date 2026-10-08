//! Strict session evidence codec; no secret or current credential lookup is needed.

use super::*;
use crate::{AuthenticationEvidence, PrimaryAuthentication, SecondaryAuthentication};
use xolotl_types::ValueMap;

fn fields<'a>(value: &'a Value, names: &[&str]) -> Result<&'a ValueMap, AuthError> {
    let map = value.as_map().ok_or(AuthError::InvalidSession)?;
    if map.len() != names.len() || names.iter().any(|name| !map.contains_key(name)) {
        return Err(AuthError::InvalidSession);
    }
    Ok(map)
}

fn string(map: &ValueMap, key: &str) -> Result<String, AuthError> {
    str_field(map, key).ok_or(AuthError::InvalidSession)
}

fn timestamp(map: &ValueMap) -> Result<i64, AuthError> {
    int_field(map, "verified_at").ok_or(AuthError::InvalidSession)
}

fn record(method: &str, verified_at: i64) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("method".into(), Value::string(method.into())),
        ("verified_at".into(), Value::integer(verified_at)),
    ])
}

impl AuthenticationEvidence {
    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        let primary_valid = self.primary.verified_at() >= 0
            && match &self.primary {
                PrimaryAuthentication::Password { .. } => true,
                PrimaryAuthentication::PublicKey { credential_key, .. } => {
                    credentials::canonical_public_key(credential_key)
                        .is_ok_and(|canonical| &canonical == credential_key)
                }
                PrimaryAuthentication::PasskeyUv { credential_id, .. } => {
                    // Reuse the vault's bound; evidence must not impose a smaller
                    // credential limit than the verification path. This engine
                    // rejects padding and noncanonical trailing bits.
                    !credential_id.is_empty()
                        && credential_id.len() <= credentials::MAX_CREDENTIAL_BYTES
                        && URL_SAFE_NO_PAD.decode(credential_id).is_ok()
                }
                PrimaryAuthentication::External {
                    provider,
                    issuer,
                    subject,
                    verified_at,
                    authenticated_at,
                    valid_until,
                    ..
                } => {
                    [provider, issuer, subject].into_iter().all(|value| {
                        !value.is_empty()
                            && value.len() <= 1024
                            && !value.chars().any(char::is_control)
                    }) && *valid_until > *verified_at
                        && authenticated_at.is_none_or(|at| at >= 0 && at <= *verified_at)
                }
            };
        let secondary_valid = self.secondary.as_ref().is_none_or(|proof| {
            proof.verified_at() >= 0
                && match proof {
                    SecondaryAuthentication::Factor {
                        factor_id,
                        provider_id,
                        ..
                    } => {
                        credentials::valid_opaque_id(factor_id)
                            && credentials::valid_provider_id(provider_id)
                    }
                    SecondaryAuthentication::RecoveryCode { .. } => true,
                }
        });
        if primary_valid && secondary_valid {
            Ok(())
        } else {
            Err(AuthError::InvalidSession)
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::map(self.to_map())
    }

    pub(crate) fn to_map(&self) -> BTreeMap<String, Value> {
        let mut primary = record(
            match &self.primary {
                PrimaryAuthentication::Password { .. } => "password",
                PrimaryAuthentication::PublicKey { .. } => "public_key",
                PrimaryAuthentication::PasskeyUv { .. } => "passkey_uv",
                PrimaryAuthentication::External { .. } => "external",
            },
            self.primary.verified_at(),
        );
        match &self.primary {
            PrimaryAuthentication::Password { .. } => {}
            PrimaryAuthentication::PublicKey { credential_key, .. } => {
                primary.insert(
                    "credential_key".into(),
                    Value::string(credential_key.clone()),
                );
            }
            PrimaryAuthentication::PasskeyUv { credential_id, .. } => {
                primary.insert("credential_id".into(), Value::string(credential_id.clone()));
            }
            PrimaryAuthentication::External {
                provider,
                issuer,
                subject,
                authenticated_at,
                valid_until,
                assurance,
                ..
            } => {
                primary.insert("provider".into(), Value::string(provider.clone()));
                primary.insert("issuer".into(), Value::string(issuer.clone()));
                primary.insert("subject".into(), Value::string(subject.clone()));
                primary.insert(
                    "authenticated_at".into(),
                    authenticated_at.map_or(Value::null(), Value::integer),
                );
                primary.insert("valid_until".into(), Value::integer(*valid_until));
                primary.insert(
                    "assurance".into(),
                    Value::string(
                        match assurance {
                            ExternalAssurance::Primary => "primary",
                            ExternalAssurance::MultiFactor => "multi_factor",
                        }
                        .into(),
                    ),
                );
            }
        }
        let secondary = self.secondary.as_ref().map_or(Value::null(), |proof| {
            let mut fields = record(
                match proof {
                    SecondaryAuthentication::Factor { .. } => "factor",
                    SecondaryAuthentication::RecoveryCode { .. } => "recovery_code",
                },
                proof.verified_at(),
            );
            if let SecondaryAuthentication::Factor {
                factor_id,
                provider_id,
                ..
            } = proof
            {
                fields.insert("factor_id".into(), Value::string(factor_id.clone()));
                fields.insert("provider_id".into(), Value::string(provider_id.clone()));
            }
            Value::map(fields)
        });
        BTreeMap::from([
            ("primary".into(), Value::map(primary)),
            ("secondary".into(), secondary),
        ])
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, AuthError> {
        let envelope = fields(value, &["primary", "secondary"])?;
        let value = envelope.get("primary").ok_or(AuthError::InvalidSession)?;
        let primary = match value
            .as_map()
            .and_then(|map| map.get("method"))
            .and_then(Value::as_str)
        {
            Some("password") => PrimaryAuthentication::Password {
                verified_at: timestamp(fields(value, &["method", "verified_at"])?)?,
            },
            Some("public_key") => {
                let map = fields(value, &["method", "credential_key", "verified_at"])?;
                PrimaryAuthentication::PublicKey {
                    credential_key: string(map, "credential_key")?,
                    verified_at: timestamp(map)?,
                }
            }
            Some("passkey_uv") => {
                let map = fields(value, &["method", "credential_id", "verified_at"])?;
                PrimaryAuthentication::PasskeyUv {
                    credential_id: string(map, "credential_id")?,
                    verified_at: timestamp(map)?,
                }
            }
            Some("external") => {
                let map = fields(
                    value,
                    &[
                        "method",
                        "provider",
                        "issuer",
                        "subject",
                        "verified_at",
                        "authenticated_at",
                        "valid_until",
                        "assurance",
                    ],
                )?;
                let authenticated_at = match map.get("authenticated_at") {
                    Some(value) if value.is_null() => None,
                    Some(value) => Some(value.as_int().ok_or(AuthError::InvalidSession)?),
                    None => return Err(AuthError::InvalidSession),
                };
                let assurance = match map.get("assurance").and_then(Value::as_str) {
                    Some("primary") => ExternalAssurance::Primary,
                    Some("multi_factor") => ExternalAssurance::MultiFactor,
                    _ => return Err(AuthError::InvalidSession),
                };
                PrimaryAuthentication::External {
                    provider: string(map, "provider")?,
                    issuer: string(map, "issuer")?,
                    subject: string(map, "subject")?,
                    verified_at: timestamp(map)?,
                    authenticated_at,
                    valid_until: int_field(map, "valid_until").ok_or(AuthError::InvalidSession)?,
                    assurance,
                }
            }
            _ => return Err(AuthError::InvalidSession),
        };
        let value = envelope.get("secondary").ok_or(AuthError::InvalidSession)?;
        let secondary = if value.is_null() {
            None
        } else {
            Some(
                match value
                    .as_map()
                    .and_then(|map| map.get("method"))
                    .and_then(Value::as_str)
                {
                    Some("factor") => {
                        let map = fields(
                            value,
                            &["method", "factor_id", "provider_id", "verified_at"],
                        )?;
                        SecondaryAuthentication::Factor {
                            factor_id: string(map, "factor_id")?,
                            provider_id: string(map, "provider_id")?,
                            verified_at: timestamp(map)?,
                        }
                    }
                    Some("recovery_code") => SecondaryAuthentication::RecoveryCode {
                        verified_at: timestamp(fields(value, &["method", "verified_at"])?)?,
                    },
                    _ => return Err(AuthError::InvalidSession),
                },
            )
        };
        let evidence = Self { primary, secondary };
        evidence.validate()?;
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests;
