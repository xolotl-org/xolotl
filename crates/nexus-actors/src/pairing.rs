//! External pairing & secure envelope: the pairing state driver and
//! the credential layer that makes a session's frames confidential,
//! authenticated, and tamper-evident.
//!
//! An installation holds a pre-shared key (`installation_psk`). Each frame the
//! role client sends is wrapped in a [`SecureEnvelope`] whose frame body
//! is AEAD ciphertext and whose AAD binds role, session, sequence, binding
//! generation, and credential generation. Fail-closed invariants: no
//! credential → no Ready session; a frame whose AEAD tag doesn't verify, or
//! whose generation is below the valid floor, is rejected. Pairing secrets are
//! generated inside the driver, Operations record only hash/checksum, and
//! Console gets the display secret via the one-shot edge API.

use async_trait::async_trait;
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{
    ExternalInstallationDef, Failure, ManifestDef, MethodId, Outcome, OutputMode, Path, Purity,
    Role, Value,
};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Default replay window size for secure external envelopes.
pub const DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW: usize = 64;
const MAX_SECURE_ENVELOPE_REPLAY_WINDOW: usize = 128;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate Resource with public method `invoke`:
/// `effect://external/pairing/create`, `/approve`, `/deny`, `/replace`, and
/// `effect://external/revoke`.
pub const PAIRING_METHODS: &[MethodSpec] = &[
    MethodSpec::new("create", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("approve", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("deny", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("replace", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("revoke", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

const STATE_CREATED: &str = "created";
const STATE_APPROVED: &str = "approved";
const STATE_DENIED: &str = "denied";
const STATE_EXPIRED: &str = "expired";
const STATE_REPLACED: &str = "replaced";
const STATE_REVOKED: &str = "revoked";

/// Drives external pairing management effects. It persists only
/// hashes and status records in the state plane; raw pairing secrets stay at the
/// display/transport edge.
pub struct PairingDriver {
    state: Backend,
    display_edge: PairingDisplayEdge,
}

/// One-shot edge for pairing display secrets.
///
/// Secrets staged here are consumed by Console/transport code after the
/// Pairing Operations record only hash/checksum metadata.
#[derive(Clone, Default)]
pub struct PairingDisplayEdge {
    pending_secrets: Arc<Mutex<BTreeMap<String, String>>>,
}

impl PairingDisplayEdge {
    /// Consume and remove the display secret for `pairing_id`.
    pub fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        self.pending_secrets.lock().remove(pairing_id)
    }

    fn stage_display_secret(&self, pairing_id: &str, secret: String) {
        self.pending_secrets
            .lock()
            .insert(pairing_id.to_string(), secret);
    }
}

impl PairingDriver {
    /// Create a pairing driver with a default one-shot display edge.
    pub fn new(state: Backend) -> Self {
        Self::with_display_edge(state, PairingDisplayEdge::default())
    }

    /// Create a pairing driver with an explicit display edge.
    pub fn with_display_edge(state: Backend, display_edge: PairingDisplayEdge) -> Self {
        Self {
            state,
            display_edge,
        }
    }

    /// Take the freshly generated display secret for `pairing_id`.
    ///
    /// This is intentionally not a Driver method and therefore not callable as
    /// an Operation: the secret must not appear in Fact input/outcome. Console
    /// and pairing transports use this one-shot edge after the standard
    /// `effect://external/pairing/create|replace` Operation has recorded only
    /// the hash/checksum.
    pub fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        self.display_edge.take_display_secret(pairing_id)
    }

    fn stage_display_secret(&self, pairing_id: &str, secret: String) {
        self.display_edge.stage_display_secret(pairing_id, secret);
    }

    fn pairing_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "pairing_id")?;
        Path::parse(&format!("state://kernel/external-pairings/{id}"))
            .map_err(|e| DriverError::Other(format!("invalid pairing id {id:?}: {e}")))
    }

    fn session_path(id: &str, role: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        validate_id_segment(role, "role")?;
        Path::parse(&format!("state://kernel/external-sessions/{id}/{role}"))
            .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    fn installation_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        Path::parse(&format!("state://kernel/external-installations/{id}"))
            .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    fn manifest_path(platform: &str) -> Result<Path, DriverError> {
        validate_id_segment(platform, "manifest_platform")?;
        Path::parse(&format!("state://kernel/manifests/{platform}"))
            .map_err(|e| DriverError::Other(format!("invalid manifest platform {platform:?}: {e}")))
    }

    fn revoke_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        Path::parse(&format!(
            "state://kernel/external-credential-revocations/{id}"
        ))
        .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    async fn read_record(&self, id: &str) -> Result<BTreeMap<String, Value>, DriverError> {
        let value = self
            .state
            .read(&Self::pairing_path(id)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
            .ok_or_else(|| DriverError::Other(format!("unknown pairing id {id:?}")))?;
        value
            .as_map()
            .cloned()
            .ok_or_else(|| DriverError::Other(format!("malformed pairing record {id:?}")))
    }

    async fn write_record(
        &self,
        id: &str,
        record: BTreeMap<String, Value>,
    ) -> Result<Outcome, DriverError> {
        let value = Value::Map(record);
        self.state
            .write_set(&Self::pairing_path(id)?, value.clone())
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        Ok(Outcome::Done(value))
    }

    async fn load_pairing_scope(
        &self,
        installation_id: &str,
        manifest_platform: Option<&str>,
    ) -> Result<PairingScope, DriverError> {
        validate_id_segment(installation_id, "installation_id")?;

        if let Some(value) = self
            .state
            .read(&Self::installation_path(installation_id)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
        {
            let def: ExternalInstallationDef =
                decode_state_value(&value, "ExternalInstallationDef")?;
            if def.id != installation_id {
                return Err(DriverError::Other(format!(
                    "ExternalInstallationDef.id {:?} does not match installation_id {:?}",
                    def.id, installation_id
                )));
            }
            def.validate_admission().map_err(|e| {
                DriverError::Other(format!("ExternalInstallationDef admission failed: {e}"))
            })?;
            return Ok(PairingScope {
                roles: installation_roles(&def)?,
                manifest_platform: None,
            });
        }

        let platform = manifest_platform.unwrap_or(installation_id);
        if let Some(value) = self
            .state
            .read(&Self::manifest_path(platform)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
        {
            let def: ManifestDef = decode_state_value(&value, "ManifestDef")?;
            validate_manifest_scope(&def, platform)?;
            return Ok(PairingScope {
                roles: manifest_roles(&def)?,
                manifest_platform: Some(platform.to_string()),
            });
        }

        Err(DriverError::Other(format!(
            "pairing requires an installed ExternalInstallationDef state://kernel/external-installations/{installation_id} \
             or ManifestDef state://kernel/manifests/{}",
            manifest_platform.unwrap_or(installation_id)
        )))
    }
}

#[derive(Clone, Debug)]
struct PairingScope {
    roles: Vec<String>,
    manifest_platform: Option<String>,
}

#[async_trait]
impl Driver for PairingDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let m = input.as_map().cloned().unwrap_or_default();
        match method.get() {
            // create: allocate a pairing intent and persist only a secret hash.
            0 => {
                if let Some(outcome) = reject_inline_secret(&m) {
                    return Ok(outcome);
                }
                reject_unknown_fields(
                    &m,
                    "pairing.create",
                    &[
                        "pairing_id",
                        "installation_id",
                        "manifest_platform",
                        "allowed_roles",
                        "expires_at",
                    ],
                )?;
                reject_inline_install_fields(&m, "pairing.create")?;
                reject_pairing_claim_fields(&m, "pairing.create")?;
                let pairing_id = match field_str(&m, "pairing_id") {
                    Some(id) => id.to_string(),
                    None => random_id()?,
                };
                let installation_id = required_str(&m, "installation_id")?.to_string();
                let scope = self
                    .load_pairing_scope(&installation_id, field_str(&m, "manifest_platform"))
                    .await?;
                let requested_allowed = role_values(m.get("allowed_roles"), "allowed_roles")?;
                let allowed_roles = if m.contains_key("allowed_roles") {
                    ensure_roles_allowed(&requested_allowed, &scope.roles)?;
                    requested_allowed
                } else {
                    scope.roles.clone()
                };
                let secret = random_secret()?;
                let expires_at = m.get("expires_at").and_then(|v| v.as_int()).unwrap_or(0);
                let mut record = BTreeMap::new();
                record.insert("pairing_id".into(), Value::Str(pairing_id.clone()));
                record.insert("installation_id".into(), Value::Str(installation_id));
                record.insert("state".into(), Value::Str(STATE_CREATED.into()));
                record.insert("allowed_roles".into(), string_list(allowed_roles));
                if let Some(platform) = scope.manifest_platform {
                    record.insert("manifest_platform".into(), Value::Str(platform));
                }
                record.insert("secret_hash".into(), Value::Str(hash_secret(&secret)));
                record.insert(
                    "display_checksum".into(),
                    Value::Str(display_checksum(&secret)),
                );
                record.insert("expires_at".into(), Value::Int(expires_at));
                record.insert("credential_generation".into(), Value::Int(0));
                let out = self.write_record(&pairing_id, record).await?;
                self.stage_display_secret(&pairing_id, secret);
                Ok(out)
            }
            // approve: terminally approve the intent and project external
            // Provider/Source session state.
            1 => {
                let pairing_id = required_str(&m, "pairing_id")?;
                let mut record = self.read_record(pairing_id).await?;
                ensure_not_terminal(&record)?;
                ensure_created(&record)?;
                if let Err(err) = ensure_not_expired(&mut record) {
                    let _ = self.write_record(pairing_id, record).await?;
                    return Err(err);
                }
                reject_approve_claim_fields(&m)?;
                reject_unknown_fields(&m, "pairing.approve", &["pairing_id", "approved_roles"])?;
                ensure_record_sas_verified(&record)?;
                let installation_id = field_str(&record, "installation_id")
                    .ok_or_else(|| DriverError::Other("approve requires installation_id".into()))?
                    .to_string();
                let scope = self
                    .load_pairing_scope(&installation_id, field_str(&record, "manifest_platform"))
                    .await?;
                let allowed_roles =
                    role_values(record.get("allowed_roles"), "record.allowed_roles")?;
                ensure_roles_allowed(&allowed_roles, &scope.roles)?;
                let requested_roles =
                    role_values(record.get("requested_roles"), "record.requested_roles")?;
                ensure_roles_allowed(&requested_roles, &allowed_roles)?;
                let approved_roles = if m.contains_key("approved_roles") {
                    let roles = role_values(m.get("approved_roles"), "approved_roles")?;
                    ensure_roles_allowed(&roles, &requested_roles)?;
                    roles
                } else {
                    requested_roles
                };
                ensure_roles_allowed(&approved_roles, &allowed_roles)?;
                let roles = approved_roles
                    .into_iter()
                    .map(Value::Str)
                    .collect::<Vec<_>>();
                let generation = record
                    .get("credential_generation")
                    .and_then(|v| v.as_int())
                    .unwrap_or(0)
                    + 1;
                record.insert("state".into(), Value::Str(STATE_APPROVED.into()));
                record.insert(
                    "installation_id".into(),
                    Value::Str(installation_id.clone()),
                );
                record.insert("approved_roles".into(), Value::List(roles.clone()));
                record.insert("credential_generation".into(), Value::Int(generation));
                record.insert(
                    "credential_hash".into(),
                    Value::Str(credential_hash(&installation_id, pairing_id, generation)),
                );
                for role in roles.iter().filter_map(Value::as_str) {
                    let suffix = match role {
                        "provider" => "provider",
                        "source" => "source",
                        _ => continue,
                    };
                    let mut ext = BTreeMap::new();
                    ext.insert(
                        "installation_id".into(),
                        Value::Str(installation_id.clone()),
                    );
                    ext.insert("role".into(), Value::Str(role.into()));
                    ext.insert("pairing_id".into(), Value::Str(pairing_id.into()));
                    ext.insert("credential_generation".into(), Value::Int(generation));
                    ext.insert("state".into(), Value::Str("ready".into()));
                    self.state
                        .write_set(
                            &Self::session_path(&installation_id, suffix)?,
                            Value::Map(ext),
                        )
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                self.write_record(pairing_id, record).await
            }
            // deny: terminally deny an intent.
            2 => {
                reject_unknown_fields(&m, "pairing.deny", &["pairing_id"])?;
                let pairing_id = required_str(&m, "pairing_id")?;
                let mut record = self.read_record(pairing_id).await?;
                ensure_not_terminal(&record)?;
                record.insert("state".into(), Value::Str(STATE_DENIED.into()));
                self.write_record(pairing_id, record).await
            }
            // replace: mark the old intent replaced and create a fresh intent.
            3 => {
                if let Some(outcome) = reject_inline_secret(&m) {
                    return Ok(outcome);
                }
                reject_unknown_fields(
                    &m,
                    "pairing.replace",
                    &[
                        "pairing_id",
                        "replacement_pairing_id",
                        "installation_id",
                        "manifest_platform",
                        "allowed_roles",
                        "expires_at",
                    ],
                )?;
                reject_inline_install_fields(&m, "pairing.replace")?;
                reject_pairing_claim_fields(&m, "pairing.replace")?;
                let pairing_id = required_str(&m, "pairing_id")?;
                let mut old = self.read_record(pairing_id).await?;
                ensure_not_terminal(&old)?;
                let replacement_id = match field_str(&m, "replacement_pairing_id") {
                    Some(id) => id.to_string(),
                    None => random_id()?,
                };
                old.insert("state".into(), Value::Str(STATE_REPLACED.into()));
                old.insert(
                    "replacement_pairing_id".into(),
                    Value::Str(replacement_id.clone()),
                );
                self.state
                    .write_set(&Self::pairing_path(pairing_id)?, Value::Map(old.clone()))
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;

                let installation_id = field_str(&m, "installation_id")
                    .or_else(|| field_str(&old, "installation_id"))
                    .ok_or_else(|| DriverError::Other("replace requires installation_id".into()))?
                    .to_string();
                let manifest_platform = field_str(&m, "manifest_platform")
                    .or_else(|| field_str(&old, "manifest_platform"));
                let scope = self
                    .load_pairing_scope(&installation_id, manifest_platform)
                    .await?;
                let requested_allowed = if m.contains_key("allowed_roles") {
                    role_values(m.get("allowed_roles"), "allowed_roles")?
                } else {
                    role_values(old.get("allowed_roles"), "record.allowed_roles")?
                };
                let allowed_roles =
                    if requested_allowed.is_empty() && !m.contains_key("allowed_roles") {
                        scope.roles.clone()
                    } else {
                        ensure_roles_allowed(&requested_allowed, &scope.roles)?;
                        requested_allowed
                    };
                let secret = random_secret()?;
                let expires_at = m.get("expires_at").and_then(|v| v.as_int()).unwrap_or(0);
                let mut replacement = BTreeMap::new();
                replacement.insert("pairing_id".into(), Value::Str(replacement_id.clone()));
                replacement.insert("installation_id".into(), Value::Str(installation_id));
                replacement.insert("state".into(), Value::Str(STATE_CREATED.into()));
                replacement.insert("allowed_roles".into(), string_list(allowed_roles));
                if let Some(platform) = scope.manifest_platform {
                    replacement.insert("manifest_platform".into(), Value::Str(platform));
                }
                replacement.insert("secret_hash".into(), Value::Str(hash_secret(&secret)));
                replacement.insert(
                    "display_checksum".into(),
                    Value::Str(display_checksum(&secret)),
                );
                replacement.insert("expires_at".into(), Value::Int(expires_at));
                replacement.insert("replaces".into(), Value::Str(pairing_id.into()));
                replacement.insert("credential_generation".into(), Value::Int(0));
                let out = self.write_record(&replacement_id, replacement).await?;
                self.stage_display_secret(&replacement_id, secret);
                Ok(out)
            }
            // revoke: invalidate an external installation.
            4 => {
                reject_unknown_fields(
                    &m,
                    "external.revoke",
                    &["installation_id", "credential_generation_floor"],
                )?;
                let installation_id = required_str(&m, "installation_id")?;
                let generation_floor = m
                    .get("credential_generation_floor")
                    .and_then(|v| v.as_int())
                    .unwrap_or(1)
                    .max(1);
                let mut record = BTreeMap::new();
                record.insert("installation_id".into(), Value::Str(installation_id.into()));
                record.insert("state".into(), Value::Str(STATE_REVOKED.into()));
                record.insert(
                    "credential_generation_floor".into(),
                    Value::Int(generation_floor),
                );
                self.state
                    .write_set(
                        &Self::revoke_path(installation_id)?,
                        Value::Map(record.clone()),
                    )
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Map(record)))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn field_str<'a>(m: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Value::as_str)
}

fn required_str<'a>(m: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str, DriverError> {
    field_str(m, key).ok_or_else(|| DriverError::Other(format!("{key} is required")))
}

fn validate_id_segment(id: &str, label: &str) -> Result<(), DriverError> {
    if id.is_empty()
        || !id.is_ascii()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(DriverError::Other(format!(
            "{label} must contain only ASCII letters, digits, '_' or '-'"
        )));
    }
    Ok(())
}

fn string_list(values: Vec<String>) -> Value {
    Value::List(values.into_iter().map(Value::Str).collect())
}

fn role_values(v: Option<&Value>, field: &str) -> Result<Vec<String>, DriverError> {
    let roles = match v {
        None => Vec::new(),
        Some(Value::Str(s)) => vec![s.clone()],
        Some(Value::List(items)) => {
            let mut roles = Vec::with_capacity(items.len());
            for item in items {
                let Some(role) = item.as_str() else {
                    return Err(DriverError::Other(format!(
                        "{field} must contain only role strings"
                    )));
                };
                roles.push(role.to_string());
            }
            roles
        }
        Some(_) => {
            return Err(DriverError::Other(format!(
                "{field} must be a string or list of strings"
            )));
        }
    };

    let mut out = Vec::with_capacity(roles.len());
    for role in roles {
        if out.iter().any(|seen| seen == &role) {
            return Err(DriverError::Other(format!(
                "{field} contains duplicate role {role:?}"
            )));
        }
        out.push(role);
    }
    Ok(out)
}

fn ensure_not_terminal(record: &BTreeMap<String, Value>) -> Result<(), DriverError> {
    match field_str(record, "state") {
        Some(STATE_APPROVED | STATE_DENIED | STATE_EXPIRED | STATE_REPLACED | STATE_REVOKED) => {
            Err(DriverError::Other("pairing intent is terminal".into()))
        }
        _ => Ok(()),
    }
}

fn ensure_created(record: &BTreeMap<String, Value>) -> Result<(), DriverError> {
    match field_str(record, "state") {
        Some(STATE_CREATED) => Ok(()),
        Some(state) => Err(DriverError::Other(format!(
            "pairing intent is not approvable in state {state:?}"
        ))),
        None => Err(DriverError::Other("pairing intent has no state".into())),
    }
}

fn ensure_not_expired(record: &mut BTreeMap<String, Value>) -> Result<(), DriverError> {
    let expires_at = record
        .get("expires_at")
        .and_then(Value::as_int)
        .unwrap_or(0);
    if expires_at > 0 && expires_at <= nexus_kernel::now_millis() {
        record.insert("state".into(), Value::Str(STATE_EXPIRED.into()));
        return Err(DriverError::Other("pairing intent has expired".into()));
    }
    Ok(())
}

fn ensure_record_sas_verified(record: &BTreeMap<String, Value>) -> Result<(), DriverError> {
    if matches!(
        record.get("sas_verified").and_then(Value::as_bool),
        Some(true)
    ) {
        Ok(())
    } else {
        Err(DriverError::Other(
            "approve requires an EndpointSupervisor-locked sas_verified claim".into(),
        ))
    }
}

fn ensure_roles_allowed(roles: &[String], allowed: &[String]) -> Result<(), DriverError> {
    if roles.is_empty() {
        return Err(DriverError::Other(
            "approve requires at least one role".into(),
        ));
    }
    for role in roles {
        if !matches!(role.as_str(), "provider" | "source") {
            return Err(DriverError::Other(format!(
                "unknown external role {role:?}"
            )));
        }
        if !allowed.iter().any(|allowed| allowed == role) {
            return Err(DriverError::Other(format!(
                "requested role {role:?} is not allowed for this pairing"
            )));
        }
    }
    Ok(())
}

fn reject_inline_secret(m: &BTreeMap<String, Value>) -> Option<Outcome> {
    if m.contains_key("pairing_secret") {
        return Some(Outcome::Fail(Failure::InvalidInput {
            reason: "pairing_secret must be generated by PairingDriver and exposed only through the display edge".into(),
        }));
    }
    None
}

fn reject_unknown_fields(
    m: &BTreeMap<String, Value>,
    method: &str,
    allowed: &[&str],
) -> Result<(), DriverError> {
    for key in m.keys() {
        if !allowed.iter().any(|allowed| allowed == key) {
            return Err(DriverError::Other(format!(
                "{method} does not accept field {key:?}"
            )));
        }
    }
    Ok(())
}

fn reject_inline_install_fields(
    m: &BTreeMap<String, Value>,
    method: &str,
) -> Result<(), DriverError> {
    for key in [
        "provides",
        "emits",
        "namespace",
        "config_schema",
        "config",
        "transport",
        "trust",
        "capabilities",
    ] {
        if m.contains_key(key) {
            return Err(DriverError::Other(format!(
                "{method} must reference an existing ExternalInstallationDef or ManifestDef; field {key:?} is not accepted"
            )));
        }
    }
    Ok(())
}

fn reject_pairing_claim_fields(
    m: &BTreeMap<String, Value>,
    method: &str,
) -> Result<(), DriverError> {
    for key in [
        "sas_verified",
        "requested_roles",
        "roles",
        "approved_roles",
        "claim",
        "registry_hash",
    ] {
        if m.contains_key(key) {
            return Err(DriverError::Other(format!(
                "{method} must not carry locked pairing claim field {key:?}"
            )));
        }
    }
    Ok(())
}

fn reject_approve_claim_fields(m: &BTreeMap<String, Value>) -> Result<(), DriverError> {
    reject_inline_install_fields(m, "pairing.approve")?;
    for key in [
        "sas_verified",
        "requested_roles",
        "roles",
        "allowed_roles",
        "installation_id",
        "manifest_platform",
        "claim",
        "registry_hash",
    ] {
        if m.contains_key(key) {
            return Err(DriverError::Other(format!(
                "pairing.approve must consume locked record claims; field {key:?} is not accepted"
            )));
        }
    }
    Ok(())
}

fn decode_state_value<T: DeserializeOwned>(value: &Value, label: &str) -> Result<T, DriverError> {
    let json = serde_json::to_value(value)
        .map_err(|e| DriverError::Other(format!("{label} serialization failed: {e}")))?;
    serde_json::from_value(json)
        .map_err(|e| DriverError::Other(format!("{label} is malformed: {e}")))
}

fn validate_manifest_scope(def: &ManifestDef, platform: &str) -> Result<(), DriverError> {
    if def.platform != platform {
        return Err(DriverError::Other(format!(
            "ManifestDef.platform {:?} does not match {platform:?}",
            def.platform
        )));
    }
    if def.version == 0 {
        return Err(DriverError::Other(
            "ManifestDef.version must be a positive config revision".into(),
        ));
    }
    if def.supported_transports.is_empty() {
        return Err(DriverError::Other(
            "ManifestDef.supported_transports must not be empty".into(),
        ));
    }
    if !def
        .supported_transports
        .iter()
        .any(|transport| transport == &def.default_transport)
    {
        return Err(DriverError::Other(
            "ManifestDef.default_transport must be listed in supported_transports".into(),
        ));
    }
    if def.projections.is_empty() {
        return Err(DriverError::Other(
            "ManifestDef.projections must not be empty".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for projection in &def.projections {
        if !seen.insert(projection.id.clone()) {
            return Err(DriverError::Other(format!(
                "ManifestDef contains duplicate projection id {:?}",
                projection.id
            )));
        }
        projection
            .validate_admission(
                platform,
                nexus_types::TrustLevel::Sandboxed,
                &def.default_transport,
            )
            .map_err(|e| {
                DriverError::Other(format!("ManifestDef projection admission failed: {e}"))
            })?;
    }
    Ok(())
}

fn manifest_roles(def: &ManifestDef) -> Result<Vec<String>, DriverError> {
    let mut roles = Vec::new();
    for projection in &def.projections {
        let role = role_name(projection.role).to_string();
        if !roles.iter().any(|seen| seen == &role) {
            roles.push(role);
        }
    }
    if roles.is_empty() {
        Err(DriverError::Other(
            "ManifestDef must declare at least one projection role".into(),
        ))
    } else {
        Ok(roles)
    }
}

fn installation_roles(def: &ExternalInstallationDef) -> Result<Vec<String>, DriverError> {
    let mut roles = Vec::new();
    for projection in &def.projections {
        let role = role_name(projection.role).to_string();
        if !roles.iter().any(|seen| seen == &role) {
            roles.push(role);
        }
    }
    if roles.is_empty() {
        Err(DriverError::Other(
            "ExternalInstallationDef must declare at least one projection role".into(),
        ))
    } else {
        Ok(roles)
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Provider => "provider",
        Role::Source => "source",
    }
}

fn random_id() -> Result<String, DriverError> {
    random_bytes()
        .map(|bytes| format!("pair-{}", hex(&bytes[..8])))
        .map_err(|e| DriverError::Other(format!("pairing id generation failed: {e}")))
}

fn random_secret() -> Result<String, DriverError> {
    random_bytes()
        .map(|bytes| hex(&bytes))
        .map_err(|e| DriverError::Other(format!("pairing secret generation failed: {e}")))
}

fn random_bytes() -> Result<[u8; 32], getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn hash_secret(secret: &str) -> String {
    let mut h = Hasher::new();
    h.update(b"nexus-external-pairing-secret-v1");
    h.update(secret.as_bytes());
    h.finalize().to_hex().to_string()
}

fn display_checksum(secret: &str) -> String {
    hash_secret(secret).chars().take(8).collect()
}

fn credential_hash(installation_id: &str, pairing_id: &str, generation: i64) -> String {
    let mut h = Hasher::new();
    h.update(b"nexus-external-credential-record-v1");
    h.update(installation_id.as_bytes());
    h.update(pairing_id.as_bytes());
    h.update(&generation.to_le_bytes());
    h.finalize().to_hex().to_string()
}

/// A paired installation's credential. The `psk` is the secret; it is
/// never serialized into a Fact or a model-readable Value — it lives only in the
/// daemon's credential store and at the transport boundary.
#[derive(Clone)]
pub struct ExternalCredential {
    /// Installation this credential belongs to.
    pub installation_id: String,
    /// The current credential generation; a revoke bumps it.
    pub generation: u64,
    psk: [u8; 32],
}

impl ExternalCredential {
    /// Mint a credential from raw PSK bytes (e.g. from a pairing exchange).
    pub fn new(installation_id: impl Into<String>, generation: u64, psk: [u8; 32]) -> Self {
        Self {
            installation_id: installation_id.into(),
            generation,
            psk,
        }
    }

    /// Derive a credential from a pairing secret string: the PSK is
    /// the blake3 hash of the installation id + the pairing secret, so the same
    /// pair always derives the same key deterministically.
    pub fn from_pairing(
        installation_id: impl Into<String>,
        pairing_secret: &str,
        generation: u64,
    ) -> Self {
        let id = installation_id.into();
        let mut h = Hasher::new();
        h.update(b"nexus-installation-psk-v1");
        h.update(id.as_bytes());
        h.update(pairing_secret.as_bytes());
        Self {
            installation_id: id,
            generation,
            psk: *h.finalize().as_bytes(),
        }
    }

    /// Seal `payload` into an AEAD envelope. Convenience form for
    /// tests and callers that do not need to override the default AAD.
    pub fn seal(&self, payload: &[u8]) -> Result<SecureEnvelope, EnvelopeError> {
        self.seal_with_aad(payload, EnvelopeAad::default())
    }

    /// Seal `payload` into an AEAD envelope: ciphertext hides the
    /// frame body, while AAD binds the generation, role/session, seq, binding
    /// generation, and credential generation so a frame cannot be replayed under
    /// a different session or generation.
    pub fn seal_with_aad(
        &self,
        payload: &[u8],
        aad: EnvelopeAad,
    ) -> Result<SecureEnvelope, EnvelopeError> {
        let mut nonce_prefix = [0u8; 12];
        getrandom::fill(&mut nonce_prefix).map_err(|_| EnvelopeError::Crypto)?;
        let seq = aad.seq;
        let ciphertext = self
            .cipher(&aad)?
            .encrypt(
                Nonce::from_slice(&nonce_bytes(&nonce_prefix, seq)),
                Payload {
                    msg: payload,
                    aad: &aad_bytes(&self.installation_id, self.generation, &aad),
                },
            )
            .map_err(|_| EnvelopeError::Crypto)?;
        Ok(SecureEnvelope {
            installation_id: self.installation_id.clone(),
            generation: self.generation,
            aad,
            nonce_prefix,
            ciphertext,
        })
    }

    /// Verify an envelope against this credential: the
    /// installation must match, the generation must be ≥ the valid floor, and
    /// the AEAD tag must verify. Returns plaintext on success.
    pub fn open(&self, env: &SecureEnvelope, valid_floor: u64) -> Result<Vec<u8>, EnvelopeError> {
        if env.installation_id != self.installation_id {
            return Err(EnvelopeError::WrongInstallation);
        }
        if env.generation < valid_floor {
            return Err(EnvelopeError::RevokedGeneration);
        }
        if env.generation != self.generation {
            return Err(EnvelopeError::BadAead);
        }
        self.cipher(&env.aad)?
            .decrypt(
                Nonce::from_slice(&nonce_bytes(&env.nonce_prefix, env.aad.seq)),
                Payload {
                    msg: &env.ciphertext,
                    aad: &aad_bytes(&env.installation_id, env.generation, &env.aad),
                },
            )
            .map_err(|_| EnvelopeError::BadAead)
    }

    /// Verify and open `env` through `replay_window`.
    pub fn open_with_replay_window(
        &self,
        env: &SecureEnvelope,
        valid_floor: u64,
        replay_window: &mut SecureEnvelopeReplayWindow,
    ) -> Result<Vec<u8>, EnvelopeError> {
        validate_envelope_aad(env)?;
        let decision = replay_window.check(env.aad.seq)?;
        let plaintext = self.open(env, valid_floor)?;
        replay_window.commit(decision);
        Ok(plaintext)
    }

    /// Verify and open `env` after checking the accepted key epoch.
    pub fn open_with_replay_window_and_epoch_gate(
        &self,
        env: &SecureEnvelope,
        valid_floor: u64,
        replay_window: &mut SecureEnvelopeReplayWindow,
        epoch_gate: &SecureEnvelopeEpochGate,
    ) -> Result<Vec<u8>, EnvelopeError> {
        validate_envelope_aad(env)?;
        epoch_gate.check(&env.aad)?;
        let decision = replay_window.check(env.aad.seq)?;
        let plaintext = self.open(env, valid_floor)?;
        replay_window.commit(decision);
        Ok(plaintext)
    }

    fn cipher(&self, aad: &EnvelopeAad) -> Result<ChaCha20Poly1305, EnvelopeError> {
        let hk = Hkdf::<Sha256>::new(
            Some(b"nexus/external/session-envelope/chacha20poly1305/v1"),
            &self.psk,
        );
        let mut key = [0u8; 32];
        hk.expand(
            &aad_bytes(&self.installation_id, self.generation, aad),
            &mut key,
        )
        .map_err(|_| EnvelopeError::Crypto)?;
        Ok(ChaCha20Poly1305::new((&key).into()))
    }
}

/// Bounded replay window for one secure external envelope stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureEnvelopeReplayWindow {
    window_size: usize,
    highest: Option<u64>,
    seen: u128,
}

impl Default for SecureEnvelopeReplayWindow {
    fn default() -> Self {
        Self {
            window_size: DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW,
            highest: None,
            seen: 0,
        }
    }
}

impl SecureEnvelopeReplayWindow {
    /// Create a replay window with `window_size` sequence numbers.
    pub fn new(window_size: usize) -> Result<Self, EnvelopeError> {
        if window_size == 0 || window_size > MAX_SECURE_ENVELOPE_REPLAY_WINDOW {
            return Err(EnvelopeError::InvalidReplayWindow);
        }
        Ok(Self {
            window_size,
            highest: None,
            seen: 0,
        })
    }

    /// Accept `seq` and record it in the replay window.
    pub fn accept(&mut self, seq: u64) -> Result<(), EnvelopeError> {
        let decision = self.check(seq)?;
        self.commit(decision);
        Ok(())
    }

    fn check(&self, seq: u64) -> Result<ReplayWindowDecision, EnvelopeError> {
        let Some(highest) = self.highest else {
            if seq >= self.window_size as u64 {
                return Err(EnvelopeError::SequenceTooFarAhead);
            }
            return Ok(ReplayWindowDecision::First(seq));
        };

        if seq > highest {
            let advance = seq - highest;
            if advance >= self.window_size as u64 {
                return Err(EnvelopeError::SequenceTooFarAhead);
            }
            return Ok(ReplayWindowDecision::Advance(advance));
        }

        let offset = highest - seq;
        if offset >= self.window_size as u64 {
            return Err(EnvelopeError::SequenceTooOld);
        }
        let bit = 1u128 << offset;
        if self.seen & bit != 0 {
            return Err(EnvelopeError::Replay);
        }
        Ok(ReplayWindowDecision::Within(offset))
    }

    fn commit(&mut self, decision: ReplayWindowDecision) {
        match decision {
            ReplayWindowDecision::First(seq) => {
                self.highest = Some(seq);
                self.seen = 1;
            }
            ReplayWindowDecision::Advance(advance) => {
                self.highest = self.highest.map(|highest| highest + advance);
                self.seen = ((self.seen << advance) | 1) & self.mask();
            }
            ReplayWindowDecision::Within(offset) => {
                self.seen |= 1u128 << offset;
                self.seen &= self.mask();
            }
        }
    }

    fn mask(&self) -> u128 {
        if self.window_size == MAX_SECURE_ENVELOPE_REPLAY_WINDOW {
            u128::MAX
        } else {
            (1u128 << self.window_size) - 1
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayWindowDecision {
    First(u64),
    Advance(u64),
    Within(u64),
}

/// Key-epoch policy for secure external envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureEnvelopeEpochGate {
    current_key_epoch: u64,
    drain_frame_types: Vec<String>,
}

impl Default for SecureEnvelopeEpochGate {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SecureEnvelopeEpochGate {
    /// Create a gate for the current session key epoch.
    pub fn new(current_key_epoch: u64) -> Self {
        Self {
            current_key_epoch,
            drain_frame_types: vec!["control.config_ack".into()],
        }
    }

    /// Add an old-epoch frame type accepted during drain.
    pub fn with_drain_frame_type(mut self, frame_type: impl Into<String>) -> Self {
        let frame_type = frame_type.into();
        if !frame_type.trim().is_empty() && !self.drain_frame_types.contains(&frame_type) {
            self.drain_frame_types.push(frame_type);
        }
        self
    }

    /// Return true when `aad` may be opened under the epoch policy.
    pub fn check(&self, aad: &EnvelopeAad) -> Result<(), EnvelopeError> {
        if aad.key_epoch == self.current_key_epoch {
            return Ok(());
        }
        if aad.key_epoch > self.current_key_epoch {
            return Err(EnvelopeError::InvalidKeyEpoch);
        }
        if self
            .drain_frame_types
            .iter()
            .any(|frame_type| frame_type == &aad.frame_type)
        {
            Ok(())
        } else {
            Err(EnvelopeError::InvalidKeyEpoch)
        }
    }
}

/// Authenticated data for one secure external frame. These fields remain
/// plaintext and are covered by the AEAD tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeAad {
    /// Envelope format version.
    pub version: u32,
    /// Projection id for the frame's role session.
    pub projection_id: String,
    /// Role name bound into the frame.
    pub role: String,
    /// Session id bound into the frame.
    pub session_id: String,
    /// Monotonic frame sequence number.
    pub seq: u64,
    /// Business/control frame type.
    pub frame_type: String,
    /// Binding generation observed by the sender.
    pub binding_generation: u64,
    /// Credential generation observed by the sender.
    pub credential_generation: u64,
    /// Hash of the negotiated session transcript.
    pub transcript_hash: Vec<u8>,
    /// Session key epoch used to seal this frame.
    pub key_epoch: u64,
}

impl Default for EnvelopeAad {
    fn default() -> Self {
        Self {
            version: 1,
            projection_id: String::new(),
            role: String::new(),
            session_id: String::new(),
            seq: 0,
            frame_type: "frame".into(),
            binding_generation: 0,
            credential_generation: 0,
            transcript_hash: Vec::new(),
            key_epoch: 0,
        }
    }
}

/// An AEAD-protected frame envelope. The ciphertext is the serialized
/// business/control frame; AAD binds the envelope to the session/generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureEnvelope {
    /// Installation id the envelope is for.
    pub installation_id: String,
    /// Credential generation used to seal the frame.
    pub generation: u64,
    /// Authenticated frame metadata.
    pub aad: EnvelopeAad,
    /// Random nonce prefix; combined with `aad.seq`.
    pub nonce_prefix: [u8; 12],
    /// Encrypted serialized frame body.
    pub ciphertext: Vec<u8>,
}

/// Why an envelope failed to open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// The envelope names a different installation than the credential.
    WrongInstallation,
    /// The generation is below the valid floor (revoked).
    RevokedGeneration,
    /// AEAD encryption failed.
    Crypto,
    /// The AEAD tag did not verify (tampered, wrong key, wrong AAD, or wrong
    /// generation).
    BadAead,
    /// The authenticated metadata is not a valid external frame header.
    InvalidAad,
    /// The frame sequence number was already accepted.
    Replay,
    /// The frame sequence number is older than the retained replay window.
    SequenceTooOld,
    /// The frame sequence number is too far ahead of the accepted window.
    SequenceTooFarAhead,
    /// The replay window size is outside the supported range.
    InvalidReplayWindow,
    /// The envelope key epoch is not accepted for this session.
    InvalidKeyEpoch,
}

fn validate_envelope_aad(env: &SecureEnvelope) -> Result<(), EnvelopeError> {
    let aad = &env.aad;
    if aad.version != 1
        || aad.projection_id.is_empty()
        || aad.role.is_empty()
        || aad.session_id.is_empty()
        || aad.frame_type.is_empty()
        || aad.credential_generation != env.generation
        || aad.transcript_hash.len() != 32
    {
        return Err(EnvelopeError::InvalidAad);
    }
    Ok(())
}

fn aad_bytes(installation_id: &str, generation: u64, aad: &EnvelopeAad) -> Vec<u8> {
    let mut out = Vec::new();
    aad_push_bytes(&mut out, b"nexus-secure-external-envelope-v1");
    aad_push_bytes(&mut out, installation_id.as_bytes());
    aad_push_bytes(&mut out, &generation.to_le_bytes());
    aad_push_bytes(&mut out, &aad.version.to_le_bytes());
    aad_push_bytes(&mut out, aad.projection_id.as_bytes());
    aad_push_bytes(&mut out, aad.role.as_bytes());
    aad_push_bytes(&mut out, aad.session_id.as_bytes());
    aad_push_bytes(&mut out, &aad.seq.to_le_bytes());
    aad_push_bytes(&mut out, aad.frame_type.as_bytes());
    aad_push_bytes(&mut out, &aad.binding_generation.to_le_bytes());
    aad_push_bytes(&mut out, &aad.credential_generation.to_le_bytes());
    aad_push_bytes(&mut out, &aad.transcript_hash);
    aad_push_bytes(&mut out, &aad.key_epoch.to_le_bytes());
    out
}

fn aad_push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn nonce_bytes(prefix: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *prefix;
    for (dst, src) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *dst ^= src;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_state::InMemoryBackend;
    use nexus_types::{EffectCapability, IdentityRef, ProcessId, Transport, TrustLevel};
    use std::sync::Arc;

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn driver() -> (PairingDriver, Backend) {
        let state: Backend = Arc::new(InMemoryBackend::new());
        (PairingDriver::new(state.clone()), state)
    }

    fn external_installation(id: &str, role: Role) -> Value {
        let projection = match role {
            Role::Provider => nexus_types::ExternalProjectionDef {
                id: "provider".into(),
                role,
                namespace: Some(Path::parse(&format!("effect://external-provider/{id}")).unwrap()),
                provides: vec![EffectCapability::new(
                    format!("effect://external-provider/{id}/search"),
                    Purity::Idempotent,
                )],
                emits: None,
                version: 1,
            },
            Role::Source => nexus_types::ExternalProjectionDef {
                id: "source".into(),
                role,
                namespace: None,
                provides: vec![],
                emits: Some(nexus_types::EventSource {
                    sink: nexus_types::sandboxed_source_event_sink_path(id, "source").unwrap(),
                    purity: Purity::Effectful,
                    event_schema: None,
                    max_inline_payload_bytes: 65_536,
                    capacity: nexus_types::external::StreamCapacity {
                        max_events: 1024,
                        on_overflow: nexus_types::external::OverflowPolicy::DropOldest,
                    },
                    rate_limit: None,
                    commands: false,
                    command_schema: None,
                    command_result_schema: None,
                }),
                version: 1,
            },
        };
        let def = ExternalInstallationDef {
            id: id.into(),
            platform: id.into(),
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![projection],
            version: 1,
        };
        serde_json::from_value(serde_json::to_value(def).unwrap()).unwrap()
    }

    async fn install_external(state: &Backend, id: &str, role: Role) {
        state
            .write_set(
                &Path::parse(&format!("state://kernel/external-installations/{id}")).unwrap(),
                external_installation(id, role),
            )
            .await
            .unwrap();
    }

    async fn lock_pairing_claim(
        state: &Backend,
        pairing_id: &str,
        requested_roles: &[&str],
        sas_verified: bool,
    ) {
        let path = PairingDriver::pairing_path(pairing_id).unwrap();
        let mut record = state
            .read(&path)
            .await
            .unwrap()
            .unwrap()
            .as_map()
            .unwrap()
            .clone();
        record.insert("sas_verified".into(), Value::Bool(sas_verified));
        record.insert(
            "requested_roles".into(),
            Value::List(
                requested_roles
                    .iter()
                    .map(|role| Value::Str((*role).into()))
                    .collect(),
            ),
        );
        state.write_set(&path, Value::Map(record)).await.unwrap();
    }

    #[tokio::test]
    async fn pairing_create_persists_hash_without_secret() {
        let (driver, state) = driver();
        install_external(&state, "ext-1", Role::Provider).await;
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-1".into()));
        input.insert("installation_id".into(), Value::Str("ext-1".into()));
        input.insert(
            "allowed_roles".into(),
            Value::List(vec![Value::Str("provider".into())]),
        );
        let out = driver
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        let Outcome::Done(Value::Map(record)) = out else {
            panic!("expected pairing record");
        };
        assert_eq!(record.get("state"), Some(&Value::Str(STATE_CREATED.into())));
        assert!(!record.contains_key("pairing_secret"));
        let stored = state
            .read(&Path::parse("state://kernel/external-pairings/pair-1").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, Value::Map(record));

        let secret = driver.take_display_secret("pair-1").unwrap();
        assert_eq!(secret.len(), 64);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(driver.take_display_secret("pair-1"), None);
    }

    #[tokio::test]
    async fn pairing_create_rejects_inline_secret() {
        let (driver, _) = driver();
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-secret".into()));
        input.insert("pairing_secret".into(), Value::Str("secret".into()));
        let out = driver
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        assert!(matches!(out, Outcome::Fail(Failure::InvalidInput { .. })));
    }

    #[tokio::test]
    async fn pairing_create_requires_installed_external_scope() {
        let (driver, _) = driver();
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-missing".into()));
        input.insert("installation_id".into(), Value::Str("missing-ext".into()));
        let err = driver
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DriverError::Other(_)));
    }

    #[tokio::test]
    async fn pairing_create_rejects_unknown_identity_field() {
        let (driver, state) = driver();
        install_external(&state, "ext-unknown-field", Role::Provider).await;
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-unknown-field".into()));
        input.insert(
            "installation_id".into(),
            Value::Str("ext-unknown-field".into()),
        );
        input.insert("connection_id".into(), Value::Str("transport-conn".into()));
        let err = driver
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DriverError::Other(_)));
    }

    #[tokio::test]
    async fn pairing_create_rejects_explicit_empty_allowed_roles() {
        let (driver, state) = driver();
        install_external(&state, "ext-empty-role", Role::Provider).await;
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-empty-role".into()));
        input.insert(
            "installation_id".into(),
            Value::Str("ext-empty-role".into()),
        );
        input.insert("allowed_roles".into(), Value::List(vec![]));
        let err = driver
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DriverError::Other(_)));
    }

    #[tokio::test]
    async fn approve_projects_provider_external_state() {
        let (driver, state) = driver();
        install_external(&state, "ext-2", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-2".into()));
        create.insert("installation_id".into(), Value::Str("ext-2".into()));
        create.insert(
            "allowed_roles".into(),
            Value::List(vec![Value::Str("provider".into())]),
        );
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        lock_pairing_claim(&state, "pair-2", &["provider"], true).await;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-2".into()));
        driver
            .call(
                MethodId::new(1),
                Value::Map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        let ext = state
            .read(&Path::parse("state://kernel/external-sessions/ext-2/provider").unwrap())
            .await
            .unwrap()
            .unwrap();
        let m = ext.as_map().unwrap();
        assert_eq!(m.get("state"), Some(&Value::Str("ready".into())));
        assert_eq!(m.get("credential_generation"), Some(&Value::Int(1)));
    }

    #[tokio::test]
    async fn pairing_scope_can_come_from_multi_projection_installation() {
        let (driver, state) = driver();
        let install = nexus_types::ExternalInstallationDef {
            id: "instant_messaging_platform".into(),
            platform: "instant_messaging_platform".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![
                nexus_types::ExternalProjectionDef {
                    id: "source".into(),
                    role: Role::Source,
                    namespace: None,
                    provides: vec![],
                    emits: Some(nexus_types::EventSource {
                        sink: nexus_types::sandboxed_source_event_sink_path(
                            "instant_messaging_platform",
                            "source",
                        )
                        .unwrap(),
                        purity: Purity::Effectful,
                        event_schema: None,
                        max_inline_payload_bytes: 65_536,
                        capacity: nexus_types::external::StreamCapacity {
                            max_events: 1024,
                            on_overflow: nexus_types::external::OverflowPolicy::DropOldest,
                        },
                        rate_limit: None,
                        commands: false,
                        command_schema: None,
                        command_result_schema: None,
                    }),
                    version: 1,
                },
                nexus_types::ExternalProjectionDef {
                    id: "provider".into(),
                    role: Role::Provider,
                    namespace: Some(
                        Path::parse("effect://external-provider/instant_messaging_platform")
                            .unwrap(),
                    ),
                    provides: vec![EffectCapability::new(
                        "effect://external-provider/instant_messaging_platform/send_text",
                        Purity::Effectful,
                    )],
                    emits: None,
                    version: 1,
                },
            ],
            version: 1,
        };
        state
            .write_set(
                &Path::parse("state://kernel/external-installations/instant_messaging_platform")
                    .unwrap(),
                serde_json::from_value(serde_json::to_value(install).unwrap()).unwrap(),
            )
            .await
            .unwrap();

        let mut create = BTreeMap::new();
        create.insert(
            "pairing_id".into(),
            Value::Str("pair-instant_messaging_platform".into()),
        );
        create.insert(
            "installation_id".into(),
            Value::Str("instant_messaging_platform".into()),
        );
        create.insert(
            "allowed_roles".into(),
            Value::List(vec![
                Value::Str("source".into()),
                Value::Str("provider".into()),
            ]),
        );
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        lock_pairing_claim(
            &state,
            "pair-instant_messaging_platform",
            &["source", "provider"],
            true,
        )
        .await;
        let mut approve = BTreeMap::new();
        approve.insert(
            "pairing_id".into(),
            Value::Str("pair-instant_messaging_platform".into()),
        );
        driver
            .call(
                MethodId::new(1),
                Value::Map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        assert!(
            state
                .read(
                    &Path::parse(
                        "state://kernel/external-sessions/instant_messaging_platform/source",
                    )
                    .unwrap(),
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            state
                .read(
                    &Path::parse(
                        "state://kernel/external-sessions/instant_messaging_platform/provider",
                    )
                    .unwrap(),
                )
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn approve_requires_sas_verified() {
        let (driver, state) = driver();
        install_external(&state, "ext-sas", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-sas".into()));
        create.insert("installation_id".into(), Value::Str("ext-sas".into()));
        create.insert(
            "allowed_roles".into(),
            Value::List(vec![Value::Str("provider".into())]),
        );
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        lock_pairing_claim(&state, "pair-sas", &["provider"], false).await;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-sas".into()));
        let err = driver
            .call(
                MethodId::new(1),
                Value::Map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DriverError::Other(_)));
    }

    #[tokio::test]
    async fn approve_rejects_frontend_claim_fields() {
        let (driver, state) = driver();
        install_external(&state, "ext-claim", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-claim".into()));
        create.insert("installation_id".into(), Value::Str("ext-claim".into()));
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        lock_pairing_claim(&state, "pair-claim", &["provider"], true).await;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-claim".into()));
        approve.insert("sas_verified".into(), Value::Bool(true));
        let err = driver
            .call(
                MethodId::new(1),
                Value::Map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DriverError::Other(_)));
    }

    #[tokio::test]
    async fn approve_rejects_roles_outside_allowed_set() {
        let (driver, state) = driver();
        install_external(&state, "ext-role", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-role".into()));
        create.insert("installation_id".into(), Value::Str("ext-role".into()));
        create.insert(
            "allowed_roles".into(),
            Value::List(vec![Value::Str("provider".into())]),
        );
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        lock_pairing_claim(&state, "pair-role", &["source"], true).await;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-role".into()));
        let err = driver
            .call(
                MethodId::new(1),
                Value::Map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DriverError::Other(_)));
    }

    #[tokio::test]
    async fn approve_terminalizes_expired_intent() {
        let (driver, state) = driver();
        install_external(&state, "ext-exp", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-exp".into()));
        create.insert("installation_id".into(), Value::Str("ext-exp".into()));
        create.insert("expires_at".into(), Value::Int(1));
        create.insert(
            "allowed_roles".into(),
            Value::List(vec![Value::Str("provider".into())]),
        );
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-exp".into()));
        let err = driver
            .call(
                MethodId::new(1),
                Value::Map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DriverError::Other(_)));
        let stored = state
            .read(&Path::parse("state://kernel/external-pairings/pair-exp").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.as_map().unwrap().get("state"),
            Some(&Value::Str(STATE_EXPIRED.into()))
        );
    }

    #[tokio::test]
    async fn replace_terminalizes_old_intent_and_creates_new_one() {
        let (driver, state) = driver();
        install_external(&state, "ext-3", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-3".into()));
        create.insert("installation_id".into(), Value::Str("ext-3".into()));
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        let mut replace = BTreeMap::new();
        replace.insert("pairing_id".into(), Value::Str("pair-3".into()));
        replace.insert(
            "replacement_pairing_id".into(),
            Value::Str("pair-3b".into()),
        );
        driver
            .call(
                MethodId::new(3),
                Value::Map(replace),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        let old = state
            .read(&Path::parse("state://kernel/external-pairings/pair-3").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            old.as_map().unwrap().get("state"),
            Some(&Value::Str(STATE_REPLACED.into()))
        );
        let new = state
            .read(&Path::parse("state://kernel/external-pairings/pair-3b").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            new.as_map().unwrap().get("state"),
            Some(&Value::Str(STATE_CREATED.into()))
        );
    }

    #[tokio::test]
    async fn revoke_writes_generation_floor() {
        let (driver, state) = driver();
        let mut input = BTreeMap::new();
        input.insert("installation_id".into(), Value::Str("ext-4".into()));
        input.insert("credential_generation_floor".into(), Value::Int(7));
        driver
            .call(
                MethodId::new(4),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        let revoked = state
            .read(&Path::parse("state://kernel/external-credential-revocations/ext-4").unwrap())
            .await
            .unwrap()
            .unwrap();
        let m = revoked.as_map().unwrap();
        assert_eq!(m.get("state"), Some(&Value::Str(STATE_REVOKED.into())));
        assert_eq!(m.get("credential_generation_floor"), Some(&Value::Int(7)));
    }

    fn valid_aad(seq: u64) -> EnvelopeAad {
        EnvelopeAad {
            projection_id: "provider".into(),
            role: "provider".into(),
            session_id: "session-1".into(),
            seq,
            frame_type: "invoke".into(),
            binding_generation: 1,
            credential_generation: 1,
            transcript_hash: vec![0x42; 32],
            key_epoch: 1,
            ..EnvelopeAad::default()
        }
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let env = cred.seal(b"hello frame").unwrap();
        assert_ne!(env.ciphertext, b"hello frame");
        assert_eq!(cred.open(&env, 0).unwrap(), b"hello frame");
    }

    #[test]
    fn tampered_ciphertext_fails_aead() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut env = cred.seal(b"transfer $10").unwrap();
        env.ciphertext[0] ^= 0x01;
        assert_eq!(cred.open(&env, 0), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn tampered_aad_fails_aead() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut env = cred
            .seal_with_aad(
                b"transfer $10",
                EnvelopeAad {
                    role: "provider".into(),
                    session_id: "session-1".into(),
                    seq: 7,
                    binding_generation: 3,
                    credential_generation: 1,
                    ..EnvelopeAad::default()
                },
            )
            .unwrap();
        env.aad.binding_generation = 4;
        assert_eq!(cred.open(&env, 0), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn tampered_key_epoch_fails_aead() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut env = cred.seal_with_aad(b"invoke", valid_aad(3)).unwrap();
        env.aad.key_epoch = env.aad.key_epoch.saturating_add(1);
        assert_eq!(cred.open(&env, 0), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn wrong_psk_fails_aead() {
        let real = ExternalCredential::from_pairing("inst-1", "secret", 1);
        let attacker = ExternalCredential::from_pairing("inst-1", "guess", 1);
        let env = attacker.seal(b"frame").unwrap();
        assert_eq!(real.open(&env, 0), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn revoked_generation_is_rejected() {
        let cred = ExternalCredential::from_pairing("inst-1", "s", 2);
        let env = cred.seal(b"frame").unwrap();
        // Valid floor raised to 5 (after a revoke) → gen-2 envelope refused.
        assert_eq!(cred.open(&env, 5), Err(EnvelopeError::RevokedGeneration));
    }

    #[test]
    fn generation_is_bound_to_aead_no_replay_across_revoke() {
        // An attacker who captures a gen-1 envelope can't just bump the
        // generation field to dodge the floor — the AEAD AAD/key binds the
        // generation.
        let cred = ExternalCredential::from_pairing("inst-1", "s", 1);
        let mut env = cred.seal(b"frame").unwrap();
        env.generation = 9; // forge a higher generation
        assert_eq!(cred.open(&env, 5), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn wrong_installation_is_rejected() {
        let cred = ExternalCredential::from_pairing("inst-1", "s", 1);
        let mut env = cred.seal(b"frame").unwrap();
        env.installation_id = "inst-2".into();
        assert_eq!(cred.open(&env, 0), Err(EnvelopeError::WrongInstallation));
    }

    #[test]
    fn replay_window_accepts_first_sequence() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let env = cred.seal_with_aad(b"frame-0", valid_aad(0)).unwrap();
        let mut replay_window = SecureEnvelopeReplayWindow::default();

        assert_eq!(
            cred.open_with_replay_window(&env, 0, &mut replay_window)
                .unwrap(),
            b"frame-0"
        );
    }

    #[test]
    fn replay_window_rejects_duplicate_sequence() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let env = cred.seal_with_aad(b"frame-0", valid_aad(0)).unwrap();
        let mut replay_window = SecureEnvelopeReplayWindow::default();

        cred.open_with_replay_window(&env, 0, &mut replay_window)
            .unwrap();
        assert_eq!(
            cred.open_with_replay_window(&env, 0, &mut replay_window),
            Err(EnvelopeError::Replay)
        );
    }

    #[test]
    fn replay_window_accepts_out_of_order_once() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut replay_window = SecureEnvelopeReplayWindow::new(4).unwrap();
        let env0 = cred.seal_with_aad(b"frame-0", valid_aad(0)).unwrap();
        let env2 = cred.seal_with_aad(b"frame-2", valid_aad(2)).unwrap();
        let env1 = cred.seal_with_aad(b"frame-1", valid_aad(1)).unwrap();

        cred.open_with_replay_window(&env0, 0, &mut replay_window)
            .unwrap();
        cred.open_with_replay_window(&env2, 0, &mut replay_window)
            .unwrap();
        assert_eq!(
            cred.open_with_replay_window(&env1, 0, &mut replay_window)
                .unwrap(),
            b"frame-1"
        );
        assert_eq!(
            cred.open_with_replay_window(&env1, 0, &mut replay_window),
            Err(EnvelopeError::Replay)
        );
    }

    #[test]
    fn replay_window_rejects_too_old_sequence() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut replay_window = SecureEnvelopeReplayWindow::new(4).unwrap();
        let env0 = cred.seal_with_aad(b"frame-0", valid_aad(0)).unwrap();
        let env3 = cred.seal_with_aad(b"frame-3", valid_aad(3)).unwrap();
        let env6 = cred.seal_with_aad(b"frame-6", valid_aad(6)).unwrap();

        cred.open_with_replay_window(&env0, 0, &mut replay_window)
            .unwrap();
        cred.open_with_replay_window(&env3, 0, &mut replay_window)
            .unwrap();
        cred.open_with_replay_window(&env6, 0, &mut replay_window)
            .unwrap();
        assert_eq!(
            cred.open_with_replay_window(&env0, 0, &mut replay_window),
            Err(EnvelopeError::SequenceTooOld)
        );
    }

    #[test]
    fn replay_window_rejects_too_far_ahead_sequence() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut replay_window = SecureEnvelopeReplayWindow::new(4).unwrap();
        let env0 = cred.seal_with_aad(b"frame-0", valid_aad(0)).unwrap();
        let env4 = cred.seal_with_aad(b"frame-4", valid_aad(4)).unwrap();

        cred.open_with_replay_window(&env0, 0, &mut replay_window)
            .unwrap();
        assert_eq!(
            cred.open_with_replay_window(&env4, 0, &mut replay_window),
            Err(EnvelopeError::SequenceTooFarAhead)
        );
    }

    #[test]
    fn replay_window_does_not_commit_bad_aead() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let env = cred.seal_with_aad(b"frame-0", valid_aad(0)).unwrap();
        let mut tampered = env.clone();
        tampered.aad.binding_generation = 2;
        let mut replay_window = SecureEnvelopeReplayWindow::default();

        assert_eq!(
            cred.open_with_replay_window(&tampered, 0, &mut replay_window),
            Err(EnvelopeError::BadAead)
        );
        assert_eq!(
            cred.open_with_replay_window(&env, 0, &mut replay_window)
                .unwrap(),
            b"frame-0"
        );
    }

    #[test]
    fn replay_window_requires_session_aad_shape() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let env = cred.seal(b"frame-0").unwrap();
        let mut replay_window = SecureEnvelopeReplayWindow::default();

        assert_eq!(
            cred.open_with_replay_window(&env, 0, &mut replay_window),
            Err(EnvelopeError::InvalidAad)
        );
    }

    #[test]
    fn epoch_gate_rejects_old_business_frames_after_rekey() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut aad = valid_aad(0);
        aad.key_epoch = 1;
        aad.frame_type = "invoke".into();
        let env = cred.seal_with_aad(b"invoke", aad).unwrap();
        let mut replay_window = SecureEnvelopeReplayWindow::default();
        let epoch_gate = SecureEnvelopeEpochGate::new(2);

        assert_eq!(
            cred.open_with_replay_window_and_epoch_gate(&env, 0, &mut replay_window, &epoch_gate),
            Err(EnvelopeError::InvalidKeyEpoch)
        );
    }

    #[test]
    fn epoch_gate_rejects_old_generic_control_frames_after_rekey() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut aad = valid_aad(0);
        aad.key_epoch = 1;
        aad.frame_type = "control".into();
        let env = cred.seal_with_aad(b"close", aad).unwrap();
        let mut replay_window = SecureEnvelopeReplayWindow::default();
        let epoch_gate = SecureEnvelopeEpochGate::new(2);

        assert_eq!(
            cred.open_with_replay_window_and_epoch_gate(&env, 0, &mut replay_window, &epoch_gate),
            Err(EnvelopeError::InvalidKeyEpoch)
        );
    }

    #[test]
    fn epoch_gate_allows_old_drain_config_ack_frames_after_rekey() {
        let cred = ExternalCredential::from_pairing("inst-1", "hunter2", 1);
        let mut aad = valid_aad(0);
        aad.key_epoch = 1;
        aad.frame_type = "control.config_ack".into();
        let env = cred.seal_with_aad(b"ack", aad).unwrap();
        let mut replay_window = SecureEnvelopeReplayWindow::default();
        let epoch_gate = SecureEnvelopeEpochGate::new(2);

        assert_eq!(
            cred.open_with_replay_window_and_epoch_gate(&env, 0, &mut replay_window, &epoch_gate)
                .unwrap(),
            b"ack"
        );
    }
}
