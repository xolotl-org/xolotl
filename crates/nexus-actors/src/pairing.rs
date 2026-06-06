//! Extension pairing & secure envelope (§16.3.4): the pairing state driver and
//! the credential layer that makes a session's frames confidential,
//! authenticated, and tamper-evident.
//!
//! An installation holds a pre-shared key (`installation_psk`). Each frame the
//! extension sends is wrapped in a [`SecureExtensionEnvelope`] whose frame body
//! is AEAD ciphertext and whose AAD binds role, session, sequence, binding
//! generation, and credential generation. Fail-closed invariants (§16.3.4): no
//! credential → no Ready session; a frame whose AEAD tag doesn't verify, or
//! whose generation is below the valid floor, is rejected. Pairing secrets are
//! generated inside the driver, ordinary Operations record only hash/checksum,
//! and Console gets the display secret via the one-shot edge API rather than a
//! model-readable `Value`.

use async_trait::async_trait;
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{
    ExtensionDef, ManifestDef, MethodId, Outcome, OutputMode, Path, Purity, Role, Value,
};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate Resource with public method `invoke`:
/// `effect://extension/pairing/create`, `/approve`, `/deny`, `/replace`, and
/// `effect://extension/revoke`.
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

/// Drives the extension-pairing management effects (§16.3.4). It persists only
/// hashes and status records in the state plane; raw pairing secrets stay at the
/// display/transport edge.
pub struct PairingDriver {
    state: Backend,
    display_edge: PairingDisplayEdge,
}

#[derive(Clone, Default)]
pub struct PairingDisplayEdge {
    pending_secrets: Arc<Mutex<BTreeMap<String, String>>>,
}

impl PairingDisplayEdge {
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
    pub fn new(state: Backend) -> Self {
        Self::with_display_edge(state, PairingDisplayEdge::default())
    }

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
    /// and pairing transports use this one-shot edge after the ordinary
    /// `effect://extension/pairing/create|replace` Operation has recorded only
    /// the hash/checksum.
    pub fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        self.display_edge.take_display_secret(pairing_id)
    }

    fn stage_display_secret(&self, pairing_id: &str, secret: String) {
        self.display_edge.stage_display_secret(pairing_id, secret);
    }

    fn pairing_path(id: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://kernel/extension-pairings/{id}"))
            .map_err(|e| DriverError::Other(format!("invalid pairing id {id:?}: {e}")))
    }

    fn extension_path(id: &str, suffix: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://kernel/extensions/{id}-{suffix}"))
            .map_err(|e| DriverError::Other(format!("invalid extension id {id:?}: {e}")))
    }

    fn extension_def_path(id: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://kernel/extensions/{id}"))
            .map_err(|e| DriverError::Other(format!("invalid extension id {id:?}: {e}")))
    }

    fn manifest_path(platform: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://kernel/manifests/{platform}"))
            .map_err(|e| DriverError::Other(format!("invalid manifest platform {platform:?}: {e}")))
    }

    fn revoke_path(id: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://kernel/extensions/{id}/revoked"))
            .map_err(|e| DriverError::Other(format!("invalid extension id {id:?}: {e}")))
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
        extension_id: &str,
        manifest_platform: Option<&str>,
    ) -> Result<PairingScope, DriverError> {
        if extension_id.is_empty() {
            return Err(DriverError::Other("extension_id must not be empty".into()));
        }

        if let Some(value) = self
            .state
            .read(&Self::extension_def_path(extension_id)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
        {
            let def: ExtensionDef = decode_state_value(&value, "ExtensionDef")?;
            if def.id != extension_id {
                return Err(DriverError::Other(format!(
                    "ExtensionDef.id {:?} does not match extension_id {:?}",
                    def.id, extension_id
                )));
            }
            def.validate_admission()
                .map_err(|e| DriverError::Other(format!("ExtensionDef admission failed: {e}")))?;
            return Ok(PairingScope {
                roles: vec![role_name(def.role).into()],
                manifest_platform: None,
            });
        }

        let platform = manifest_platform.unwrap_or(extension_id);
        if let Some(value) = self
            .state
            .read(&Self::manifest_path(platform)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
        {
            let def: ManifestDef = decode_state_value(&value, "ManifestDef")?;
            validate_manifest_scope(&def, platform)?;
            return Ok(PairingScope {
                roles: vec![role_name(def.role).into()],
                manifest_platform: Some(platform.to_string()),
            });
        }

        Err(DriverError::Other(format!(
            "pairing requires an installed ExtensionDef state://kernel/extensions/{extension_id} \
             or ManifestDef state://kernel/manifests/{}",
            manifest_platform.unwrap_or(extension_id)
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
                reject_inline_secret(&m)?;
                reject_inline_install_fields(&m, "pairing.create")?;
                reject_pairing_claim_fields(&m, "pairing.create")?;
                let pairing_id = match field_str(&m, "pairing_id") {
                    Some(id) => id.to_string(),
                    None => random_id()?,
                };
                let extension_id = field_str(&m, "extension_id")
                    .map(str::to_string)
                    .unwrap_or_else(|| pairing_id.clone());
                let scope = self
                    .load_pairing_scope(&extension_id, field_str(&m, "manifest_platform"))
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
                record.insert("extension_id".into(), Value::Str(extension_id));
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
            // approve: terminally approve the intent and project provider/source
            // role state under state://kernel/extensions/*.
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
                ensure_record_sas_verified(&record)?;
                let extension_id = field_str(&record, "extension_id")
                    .ok_or_else(|| DriverError::Other("approve requires extension_id".into()))?
                    .to_string();
                let scope = self
                    .load_pairing_scope(&extension_id, field_str(&record, "manifest_platform"))
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
                record.insert("extension_id".into(), Value::Str(extension_id.clone()));
                record.insert("approved_roles".into(), Value::List(roles.clone()));
                record.insert("credential_generation".into(), Value::Int(generation));
                record.insert(
                    "credential_hash".into(),
                    Value::Str(credential_hash(&extension_id, pairing_id, generation)),
                );
                for role in roles.iter().filter_map(Value::as_str) {
                    let suffix = match role {
                        "provider" => "provider",
                        "source" => "source",
                        _ => continue,
                    };
                    let mut ext = BTreeMap::new();
                    ext.insert("extension_id".into(), Value::Str(extension_id.clone()));
                    ext.insert("role".into(), Value::Str(role.into()));
                    ext.insert("pairing_id".into(), Value::Str(pairing_id.into()));
                    ext.insert("credential_generation".into(), Value::Int(generation));
                    ext.insert("state".into(), Value::Str("ready".into()));
                    self.state
                        .write_set(
                            &Self::extension_path(&extension_id, suffix)?,
                            Value::Map(ext),
                        )
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                self.write_record(pairing_id, record).await
            }
            // deny: terminally deny an intent.
            2 => {
                let pairing_id = required_str(&m, "pairing_id")?;
                let mut record = self.read_record(pairing_id).await?;
                ensure_not_terminal(&record)?;
                record.insert("state".into(), Value::Str(STATE_DENIED.into()));
                self.write_record(pairing_id, record).await
            }
            // replace: mark the old intent replaced and create a fresh intent.
            3 => {
                reject_inline_secret(&m)?;
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

                let extension_id = field_str(&m, "extension_id")
                    .or_else(|| field_str(&old, "extension_id"))
                    .unwrap_or(&replacement_id)
                    .to_string();
                let manifest_platform = field_str(&m, "manifest_platform")
                    .or_else(|| field_str(&old, "manifest_platform"));
                let scope = self
                    .load_pairing_scope(&extension_id, manifest_platform)
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
                replacement.insert("extension_id".into(), Value::Str(extension_id));
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
            // revoke: invalidate an extension installation.
            4 => {
                let extension_id = required_str(&m, "extension_id")?;
                let generation_floor = m
                    .get("credential_generation_floor")
                    .and_then(|v| v.as_int())
                    .unwrap_or(1)
                    .max(1);
                let mut record = BTreeMap::new();
                record.insert("extension_id".into(), Value::Str(extension_id.into()));
                record.insert("state".into(), Value::Str(STATE_REVOKED.into()));
                record.insert(
                    "credential_generation_floor".into(),
                    Value::Int(generation_floor),
                );
                self.state
                    .write_set(
                        &Self::revoke_path(extension_id)?,
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
                "unknown extension role {role:?}"
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

fn reject_inline_secret(m: &BTreeMap<String, Value>) -> Result<(), DriverError> {
    if m.contains_key("pairing_secret") {
        return Err(DriverError::Other(
            "pairing_secret must be generated by PairingDriver and exposed only through the display edge".into(),
        ));
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
                "{method} must reference an existing ExtensionDef or ManifestDef; field {key:?} is not accepted"
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
        "extension_id",
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
    match def.role {
        Role::Provider if def.provides.is_empty() => Err(DriverError::Other(
            "provider ManifestDef must declare provided effects".into(),
        )),
        Role::Source if !def.provides.is_empty() => Err(DriverError::Other(
            "source ManifestDef must not declare provider effects".into(),
        )),
        _ => Ok(()),
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
    h.update(b"nexus-extension-pairing-secret-v1");
    h.update(secret.as_bytes());
    h.finalize().to_hex().to_string()
}

fn display_checksum(secret: &str) -> String {
    hash_secret(secret).chars().take(8).collect()
}

fn credential_hash(extension_id: &str, pairing_id: &str, generation: i64) -> String {
    let mut h = Hasher::new();
    h.update(b"nexus-extension-credential-record-v1");
    h.update(extension_id.as_bytes());
    h.update(pairing_id.as_bytes());
    h.update(&generation.to_le_bytes());
    h.finalize().to_hex().to_string()
}

/// A paired installation's credential (§16.3.4). The `psk` is the secret; it is
/// never serialized into a Fact or a model-readable Value — it lives only in the
/// daemon's credential store and at the transport boundary.
#[derive(Clone)]
pub struct ExtensionCredential {
    pub installation_id: String,
    /// The current credential generation; a revoke bumps it (§16.3.4).
    pub generation: u64,
    psk: [u8; 32],
}

impl ExtensionCredential {
    /// Mint a credential from raw PSK bytes (e.g. from a pairing exchange).
    pub fn new(installation_id: impl Into<String>, generation: u64, psk: [u8; 32]) -> Self {
        Self {
            installation_id: installation_id.into(),
            generation,
            psk,
        }
    }

    /// Derive a credential from a pairing secret string (§16.3.4): the PSK is
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

    /// Seal `payload` into an AEAD envelope (§16.3.4). Convenience form for
    /// tests and callers that do not need to override the default AAD.
    pub fn seal(&self, payload: &[u8]) -> SecureExtensionEnvelope {
        self.seal_with_aad(payload, EnvelopeAad::default())
            .expect("default AEAD seal succeeds with fixed-size derived key")
    }

    /// Seal `payload` into an AEAD envelope (§16.3.4): ciphertext hides the
    /// frame body, while AAD binds the generation, role/session, seq, binding
    /// generation, and credential generation so a frame cannot be replayed under
    /// a different session or generation.
    pub fn seal_with_aad(
        &self,
        payload: &[u8],
        aad: EnvelopeAad,
    ) -> Result<SecureExtensionEnvelope, EnvelopeError> {
        let mut nonce_prefix = [0u8; 12];
        getrandom::fill(&mut nonce_prefix).map_err(|_| EnvelopeError::Crypto)?;
        let seq = aad.seq;
        let ciphertext = self
            .cipher(&aad)
            .encrypt(
                Nonce::from_slice(&nonce_bytes(&nonce_prefix, seq)),
                Payload {
                    msg: payload,
                    aad: &aad_bytes(&self.installation_id, self.generation, &aad),
                },
            )
            .map_err(|_| EnvelopeError::Crypto)?;
        Ok(SecureExtensionEnvelope {
            installation_id: self.installation_id.clone(),
            generation: self.generation,
            aad,
            nonce_prefix,
            ciphertext,
        })
    }

    /// Verify an envelope against this credential (§16.3.4 fail-closed): the
    /// installation must match, the generation must be ≥ the valid floor, and
    /// the AEAD tag must verify. Returns plaintext on success.
    pub fn open<'a>(
        &self,
        env: &SecureExtensionEnvelope,
        valid_floor: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if env.installation_id != self.installation_id {
            return Err(EnvelopeError::WrongInstallation);
        }
        if env.generation < valid_floor {
            return Err(EnvelopeError::RevokedGeneration);
        }
        if env.generation != self.generation {
            return Err(EnvelopeError::BadAead);
        }
        self.cipher(&env.aad)
            .decrypt(
                Nonce::from_slice(&nonce_bytes(&env.nonce_prefix, env.aad.seq)),
                Payload {
                    msg: &env.ciphertext,
                    aad: &aad_bytes(&env.installation_id, env.generation, &env.aad),
                },
            )
            .map_err(|_| EnvelopeError::BadAead)
    }

    fn cipher(&self, aad: &EnvelopeAad) -> ChaCha20Poly1305 {
        let hk = Hkdf::<Sha256>::new(
            Some(b"nexus/extension/session-envelope/chacha20poly1305/v1"),
            &self.psk,
        );
        let mut key = [0u8; 32];
        hk.expand(
            &aad_bytes(&self.installation_id, self.generation, aad),
            &mut key,
        )
        .expect("HKDF output length is valid");
        ChaCha20Poly1305::new((&key).into())
    }
}

/// Authenticated data for one secure extension frame (§16.3.4). These fields
/// are not encrypted, but any change invalidates the AEAD tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeAad {
    pub version: u32,
    pub extension_def_id: String,
    pub role: String,
    pub session_id: String,
    pub seq: u64,
    pub frame_type: String,
    pub binding_generation: u64,
    pub credential_generation: u64,
}

impl Default for EnvelopeAad {
    fn default() -> Self {
        Self {
            version: 1,
            extension_def_id: String::new(),
            role: String::new(),
            session_id: String::new(),
            seq: 0,
            frame_type: "frame".into(),
            binding_generation: 0,
            credential_generation: 0,
        }
    }
}

/// An AEAD-protected frame envelope (§16.3.4). The ciphertext is the serialized
/// business/control frame; AAD binds the envelope to the session/generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureExtensionEnvelope {
    pub installation_id: String,
    pub generation: u64,
    pub aad: EnvelopeAad,
    pub nonce_prefix: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Why an envelope failed to open (§16.3.4 fail-closed).
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
}

fn aad_bytes(installation_id: &str, generation: u64, aad: &EnvelopeAad) -> Vec<u8> {
    [
        b"nexus-secure-extension-envelope-v1".as_slice(),
        installation_id.as_bytes(),
        &generation.to_le_bytes(),
        &aad.version.to_le_bytes(),
        aad.extension_def_id.as_bytes(),
        aad.role.as_bytes(),
        aad.session_id.as_bytes(),
        &aad.seq.to_le_bytes(),
        aad.frame_type.as_bytes(),
        &aad.binding_generation.to_le_bytes(),
        &aad.credential_generation.to_le_bytes(),
    ]
    .concat()
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

    fn extension_def(id: &str, role: Role) -> Value {
        let (provides, emits) = match role {
            Role::Provider => (
                vec![EffectCapability::new(
                    format!("effect://plugin/{id}/search"),
                    Purity::Idempotent,
                )],
                None,
            ),
            Role::Source => (
                vec![],
                Some(nexus_types::EventSource {
                    sink: Path::parse(&format!("state://plugin/{id}/events")).unwrap(),
                    purity: Purity::Effectful,
                    event_schema: None,
                }),
            ),
        };
        let def = ExtensionDef {
            id: id.into(),
            role,
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            provides,
            emits,
            namespace: Path::parse(&format!("effect://plugin/{id}")).unwrap(),
            config_schema: Value::Null,
            config: Value::Null,
            version: 1,
        };
        serde_json::from_value(serde_json::to_value(def).unwrap()).unwrap()
    }

    async fn install_extension_def(state: &Backend, id: &str, role: Role) {
        state
            .write_set(
                &Path::parse(&format!("state://kernel/extensions/{id}")).unwrap(),
                extension_def(id, role),
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
        install_extension_def(&state, "ext-1", Role::Provider).await;
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-1".into()));
        input.insert("extension_id".into(), Value::Str("ext-1".into()));
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
            .read(&Path::parse("state://kernel/extension-pairings/pair-1").unwrap())
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
    async fn pairing_create_requires_installed_extension_scope() {
        let (driver, _) = driver();
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-missing".into()));
        input.insert("extension_id".into(), Value::Str("missing-ext".into()));
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
        install_extension_def(&state, "ext-empty-role", Role::Provider).await;
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-empty-role".into()));
        input.insert("extension_id".into(), Value::Str("ext-empty-role".into()));
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
    async fn approve_projects_provider_extension_state() {
        let (driver, state) = driver();
        install_extension_def(&state, "ext-2", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-2".into()));
        create.insert("extension_id".into(), Value::Str("ext-2".into()));
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
            .read(&Path::parse("state://kernel/extensions/ext-2-provider").unwrap())
            .await
            .unwrap()
            .unwrap();
        let m = ext.as_map().unwrap();
        assert_eq!(m.get("state"), Some(&Value::Str("ready".into())));
        assert_eq!(m.get("credential_generation"), Some(&Value::Int(1)));
    }

    #[tokio::test]
    async fn approve_requires_sas_verified() {
        let (driver, state) = driver();
        install_extension_def(&state, "ext-sas", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-sas".into()));
        create.insert("extension_id".into(), Value::Str("ext-sas".into()));
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
        install_extension_def(&state, "ext-claim", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-claim".into()));
        create.insert("extension_id".into(), Value::Str("ext-claim".into()));
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
        install_extension_def(&state, "ext-role", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-role".into()));
        create.insert("extension_id".into(), Value::Str("ext-role".into()));
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
        install_extension_def(&state, "ext-exp", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-exp".into()));
        create.insert("extension_id".into(), Value::Str("ext-exp".into()));
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
            .read(&Path::parse("state://kernel/extension-pairings/pair-exp").unwrap())
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
        install_extension_def(&state, "ext-3", Role::Provider).await;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-3".into()));
        create.insert("extension_id".into(), Value::Str("ext-3".into()));
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
            .read(&Path::parse("state://kernel/extension-pairings/pair-3").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            old.as_map().unwrap().get("state"),
            Some(&Value::Str(STATE_REPLACED.into()))
        );
        let new = state
            .read(&Path::parse("state://kernel/extension-pairings/pair-3b").unwrap())
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
        input.insert("extension_id".into(), Value::Str("ext-4".into()));
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
            .read(&Path::parse("state://kernel/extensions/ext-4/revoked").unwrap())
            .await
            .unwrap()
            .unwrap();
        let m = revoked.as_map().unwrap();
        assert_eq!(m.get("state"), Some(&Value::Str(STATE_REVOKED.into())));
        assert_eq!(m.get("credential_generation_floor"), Some(&Value::Int(7)));
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let cred = ExtensionCredential::from_pairing("inst-1", "hunter2", 1);
        let env = cred.seal(b"hello frame");
        assert_ne!(env.ciphertext, b"hello frame");
        assert_eq!(cred.open(&env, 0).unwrap(), b"hello frame");
    }

    #[test]
    fn tampered_ciphertext_fails_aead() {
        let cred = ExtensionCredential::from_pairing("inst-1", "hunter2", 1);
        let mut env = cred.seal(b"transfer $10");
        env.ciphertext[0] ^= 0x01;
        assert_eq!(cred.open(&env, 0), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn tampered_aad_fails_aead() {
        let cred = ExtensionCredential::from_pairing("inst-1", "hunter2", 1);
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
    fn wrong_psk_fails_aead() {
        let real = ExtensionCredential::from_pairing("inst-1", "secret", 1);
        let attacker = ExtensionCredential::from_pairing("inst-1", "guess", 1);
        let env = attacker.seal(b"frame");
        assert_eq!(real.open(&env, 0), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn revoked_generation_is_rejected() {
        let cred = ExtensionCredential::from_pairing("inst-1", "s", 2);
        let env = cred.seal(b"frame");
        // Valid floor raised to 5 (after a revoke) → gen-2 envelope refused.
        assert_eq!(cred.open(&env, 5), Err(EnvelopeError::RevokedGeneration));
    }

    #[test]
    fn generation_is_bound_to_aead_no_replay_across_revoke() {
        // An attacker who captures a gen-1 envelope can't just bump the
        // generation field to dodge the floor — the AEAD AAD/key binds the
        // generation.
        let cred = ExtensionCredential::from_pairing("inst-1", "s", 1);
        let mut env = cred.seal(b"frame");
        env.generation = 9; // forge a higher generation
        assert_eq!(cred.open(&env, 5), Err(EnvelopeError::BadAead));
    }

    #[test]
    fn wrong_installation_is_rejected() {
        let cred = ExtensionCredential::from_pairing("inst-1", "s", 1);
        let mut env = cred.seal(b"frame");
        env.installation_id = "inst-2".into();
        assert_eq!(cred.open(&env, 0), Err(EnvelopeError::WrongInstallation));
    }
}
