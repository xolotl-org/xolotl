//! Pairing state driver and display-secret edge for external installations.

#[cfg(feature = "standard-core")]
use andrias_kernel::{Driver, DriverContext, DriverError, MethodSpec};
#[cfg(feature = "standard-core")]
use andrias_state::Backend;
#[cfg(feature = "standard-core")]
use andrias_types::{
    ExternalInstallationDef, Failure, ManifestDef, MethodId, Outcome, OutputMode, Path, Purity,
    Role, Value,
};
#[cfg(feature = "standard-core")]
use async_trait::async_trait;
use blake3::Hasher;
use parking_lot::Mutex;
#[cfg(feature = "standard-core")]
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate Resource with public method `invoke`:
/// `effect://external/pairing/create`, `/approve`, `/deny`, `/replace`, and
/// `effect://external/revoke`.
#[cfg(feature = "standard-core")]
pub(crate) const PAIRING_METHODS: &[MethodSpec] = &[
    MethodSpec::new("create", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("approve", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("deny", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("replace", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("revoke", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

#[cfg(feature = "standard-core")]
const STATE_CREATED: &str = "created";
#[cfg(feature = "standard-core")]
const STATE_APPROVED: &str = "approved";
#[cfg(feature = "standard-core")]
const STATE_DENIED: &str = "denied";
#[cfg(feature = "standard-core")]
const STATE_EXPIRED: &str = "expired";
#[cfg(feature = "standard-core")]
const STATE_REPLACED: &str = "replaced";
#[cfg(feature = "standard-core")]
const STATE_REVOKED: &str = "revoked";

/// Drives external pairing management effects. It persists only
/// hashes and status records in the state plane; raw pairing secrets stay at the
/// display/transport edge.
#[cfg(feature = "standard-core")]
pub(crate) struct PairingDriver {
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

    #[cfg(feature = "standard-core")]
    fn stage_display_secret(&self, pairing_id: &str, secret: String) {
        self.pending_secrets
            .lock()
            .insert(pairing_id.to_string(), secret);
    }
}

#[cfg(feature = "standard-core")]
impl PairingDriver {
    /// Create a pairing driver with a default one-shot display edge.
    #[cfg(test)]
    pub(crate) fn new(state: Backend) -> Self {
        Self::with_display_edge(state, PairingDisplayEdge::default())
    }

    /// Create a pairing driver with an explicit display edge.
    pub(crate) fn with_display_edge(state: Backend, display_edge: PairingDisplayEdge) -> Self {
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
    #[cfg(test)]
    pub(crate) fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        self.display_edge.take_display_secret(pairing_id)
    }

    fn stage_display_secret(&self, pairing_id: &str, secret: String) {
        self.display_edge.stage_display_secret(pairing_id, secret);
    }

    fn pairing_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "pairing_id")?;
        kernel_state_path(&["external-pairings", id])
            .map_err(|e| DriverError::Other(format!("invalid pairing id {id:?}: {e}")))
    }

    fn session_path(id: &str, role: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        validate_id_segment(role, "role")?;
        kernel_state_path(&["external-sessions", id, role])
            .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    fn installation_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        kernel_state_path(&["external-installations", id])
            .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    fn manifest_path(platform: &str) -> Result<Path, DriverError> {
        validate_id_segment(platform, "manifest_platform")?;
        kernel_state_path(&["manifests", platform])
            .map_err(|e| DriverError::Other(format!("invalid manifest platform {platform:?}: {e}")))
    }

    fn revoke_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        kernel_state_path(&["external-credential-revocations", id])
            .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    async fn read_record(&self, id: &str) -> Result<BTreeMap<String, Value>, DriverError> {
        let value = self
            .state
            .read(&Self::pairing_path(id)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
            .ok_or_else(|| DriverError::Other(format!("unknown pairing id {id:?}")))?;
        match value {
            Value::Map(record) => Ok(record),
            _ => Err(DriverError::Other(format!(
                "malformed pairing record {id:?}"
            ))),
        }
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
#[cfg(feature = "standard-core")]
struct PairingScope {
    roles: Vec<String>,
    manifest_platform: Option<String>,
}

#[async_trait]
#[cfg(feature = "standard-core")]
impl Driver for PairingDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let m = crate::input::map(input, "pairing")?;
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
                let pairing_id = match optional_str(&m, "pairing_id")? {
                    Some(id) => id.to_string(),
                    None => random_id()?,
                };
                let installation_id = required_str(&m, "installation_id")?.to_string();
                let scope = self
                    .load_pairing_scope(&installation_id, optional_str(&m, "manifest_platform")?)
                    .await?;
                let requested_allowed = role_values(m.get("allowed_roles"), "allowed_roles")?;
                let allowed_roles = if m.contains_key("allowed_roles") {
                    ensure_roles_allowed(&requested_allowed, &scope.roles)?;
                    requested_allowed
                } else {
                    scope.roles.clone()
                };
                let secret = random_secret()?;
                let expires_at = optional_nonnegative_int(&m, "expires_at", 0)?;
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
                    self.write_record(pairing_id, record).await?;
                    return Err(err);
                }
                reject_approve_claim_fields(&m)?;
                reject_unknown_fields(&m, "pairing.approve", &["pairing_id", "approved_roles"])?;
                ensure_record_sas_verified(&record)?;
                let installation_id = record_required_str(&record, "installation_id")?.to_string();
                let manifest_platform =
                    record_optional_str(&record, "manifest_platform")?.map(str::to_string);
                let scope = self
                    .load_pairing_scope(&installation_id, manifest_platform.as_deref())
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
                let generation = required_record_nonnegative_int(&record, "credential_generation")?
                    .checked_add(1)
                    .ok_or_else(|| DriverError::Other("credential_generation overflowed".into()))?;
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
                let replacement_id = match optional_str(&m, "replacement_pairing_id")? {
                    Some(id) => id.to_string(),
                    None => random_id()?,
                };
                Self::pairing_path(&replacement_id)?;
                let old_installation_id = record_required_str(&old, "installation_id")?;
                let old_manifest_platform =
                    record_optional_str(&old, "manifest_platform")?.map(str::to_string);
                let old_scope = self
                    .load_pairing_scope(old_installation_id, old_manifest_platform.as_deref())
                    .await?;
                let stored_allowed = role_values(old.get("allowed_roles"), "record.allowed_roles")?;
                ensure_roles_allowed(&stored_allowed, &old_scope.roles)?;
                required_record_nonnegative_int(&old, "expires_at")?;
                required_record_nonnegative_int(&old, "credential_generation")?;
                record_required_str(&old, "secret_hash")?;
                record_required_str(&old, "display_checksum")?;

                let installation_id = optional_str(&m, "installation_id")?
                    .unwrap_or(old_installation_id)
                    .to_string();
                let manifest_platform = match optional_str(&m, "manifest_platform")? {
                    Some(platform) => Some(platform.to_string()),
                    None => record_optional_str(&old, "manifest_platform")?.map(str::to_string),
                };
                let scope = self
                    .load_pairing_scope(&installation_id, manifest_platform.as_deref())
                    .await?;
                let allowed_roles = if m.contains_key("allowed_roles") {
                    let requested_allowed = role_values(m.get("allowed_roles"), "allowed_roles")?;
                    ensure_roles_allowed(&requested_allowed, &scope.roles)?;
                    requested_allowed
                } else {
                    ensure_roles_allowed(&stored_allowed, &scope.roles)?;
                    stored_allowed
                };
                let expires_at = optional_nonnegative_int(&m, "expires_at", 0)?;
                let secret = random_secret()?;
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

                old.insert("state".into(), Value::Str(STATE_REPLACED.into()));
                old.insert(
                    "replacement_pairing_id".into(),
                    Value::Str(replacement_id.clone()),
                );
                self.state
                    .write_set(&Self::pairing_path(pairing_id)?, Value::Map(old.clone()))
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
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
                let generation_floor = credential_generation_floor(&m)?;
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

#[cfg(feature = "standard-core")]
fn credential_generation_floor(m: &BTreeMap<String, Value>) -> Result<i64, DriverError> {
    match m.get("credential_generation_floor") {
        None => Ok(1),
        Some(Value::Int(floor)) if *floor >= 1 => Ok(*floor),
        Some(Value::Int(_)) => Err(DriverError::Other(
            "credential_generation_floor must be at least 1".into(),
        )),
        Some(_) => Err(DriverError::Other(
            "credential_generation_floor must be an integer".into(),
        )),
    }
}

#[cfg(feature = "standard-core")]
fn field_str<'a>(m: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Value::as_str)
}

#[cfg(feature = "standard-core")]
fn record_optional_str<'a>(
    record: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, DriverError> {
    match record.get(key) {
        None => Ok(None),
        Some(Value::Str(value)) if !value.is_empty() => Ok(Some(value.as_str())),
        Some(Value::Str(_)) => Err(DriverError::Other(format!(
            "pairing record field {key} must not be empty"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "pairing record field {key} must be a string"
        ))),
    }
}

#[cfg(feature = "standard-core")]
fn record_required_str<'a>(
    record: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, DriverError> {
    record_optional_str(record, key)?
        .ok_or_else(|| DriverError::Other(format!("pairing record missing {key}")))
}

#[cfg(feature = "standard-core")]
fn optional_str<'a>(
    m: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, DriverError> {
    match m.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Str(value)) if !value.is_empty() => Ok(Some(value.as_str())),
        Some(Value::Str(_)) => Err(DriverError::Other(format!("{key} must not be empty"))),
        Some(_) => Err(DriverError::Other(format!("{key} must be a string"))),
    }
}

#[cfg(feature = "standard-core")]
fn required_str<'a>(m: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str, DriverError> {
    optional_str(m, key)?.ok_or_else(|| DriverError::Other(format!("{key} is required")))
}

#[cfg(feature = "standard-core")]
fn optional_nonnegative_int(
    m: &BTreeMap<String, Value>,
    key: &str,
    default: i64,
) -> Result<i64, DriverError> {
    match m.get(key) {
        Some(Value::Null) | None => Ok(default),
        Some(Value::Int(value)) if *value >= 0 => Ok(*value),
        Some(Value::Int(_)) => Err(DriverError::Other(format!("{key} must be nonnegative"))),
        Some(_) => Err(DriverError::Other(format!("{key} must be an integer"))),
    }
}

#[cfg(feature = "standard-core")]
fn required_record_nonnegative_int(
    record: &BTreeMap<String, Value>,
    key: &str,
) -> Result<i64, DriverError> {
    match record.get(key) {
        Some(Value::Int(value)) if *value >= 0 => Ok(*value),
        Some(Value::Int(_)) => Err(DriverError::Other(format!(
            "pairing record field {key} must be nonnegative"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "pairing record field {key} must be an integer"
        ))),
        None => Err(DriverError::Other(format!("pairing record missing {key}"))),
    }
}

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
fn kernel_state_path(segments: &[&str]) -> Result<Path, andrias_types::PathError> {
    let mut path = Path::try_new("state")?.try_push("kernel")?;
    for segment in segments {
        path = path.try_push_literal(segment)?;
    }
    Ok(path)
}

#[cfg(feature = "standard-core")]
fn string_list(values: Vec<String>) -> Value {
    Value::List(values.into_iter().map(Value::Str).collect())
}

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
fn ensure_not_terminal(record: &BTreeMap<String, Value>) -> Result<(), DriverError> {
    match field_str(record, "state") {
        Some(STATE_CREATED) => Ok(()),
        Some(STATE_APPROVED | STATE_DENIED | STATE_EXPIRED | STATE_REPLACED | STATE_REVOKED) => {
            Err(DriverError::Other("pairing intent is terminal".into()))
        }
        Some(state) => Err(DriverError::Other(format!(
            "pairing intent has unknown state {state:?}"
        ))),
        None => Err(DriverError::Other("pairing intent has no state".into())),
    }
}

#[cfg(feature = "standard-core")]
fn ensure_created(record: &BTreeMap<String, Value>) -> Result<(), DriverError> {
    match field_str(record, "state") {
        Some(STATE_CREATED) => Ok(()),
        Some(state) => Err(DriverError::Other(format!(
            "pairing intent is not approvable in state {state:?}"
        ))),
        None => Err(DriverError::Other("pairing intent has no state".into())),
    }
}

#[cfg(feature = "standard-core")]
fn ensure_not_expired(record: &mut BTreeMap<String, Value>) -> Result<(), DriverError> {
    let expires_at = required_record_nonnegative_int(record, "expires_at")?;
    if expires_at > 0 && expires_at <= andrias_kernel::now_millis() {
        record.insert("state".into(), Value::Str(STATE_EXPIRED.into()));
        return Err(DriverError::Other("pairing intent has expired".into()));
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
fn reject_inline_secret(m: &BTreeMap<String, Value>) -> Option<Outcome> {
    if m.contains_key("pairing_secret") {
        return Some(Outcome::Fail(Failure::InvalidInput {
            reason: "pairing_secret must be generated by PairingDriver and exposed only through the display edge".into(),
        }));
    }
    None
}

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
fn decode_state_value<T: DeserializeOwned>(value: &Value, label: &str) -> Result<T, DriverError> {
    let json = serde_json::to_value(value)
        .map_err(|e| DriverError::Other(format!("{label} serialization failed: {e}")))?;
    serde_json::from_value(json)
        .map_err(|e| DriverError::Other(format!("{label} is malformed: {e}")))
}

#[cfg(feature = "standard-core")]
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
                andrias_types::TrustLevel::Sandboxed,
                &def.default_transport,
            )
            .map_err(|e| {
                DriverError::Other(format!("ManifestDef projection admission failed: {e}"))
            })?;
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
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

#[cfg(feature = "standard-core")]
fn role_name(role: Role) -> &'static str {
    match role {
        Role::Provider => "provider",
        Role::Source => "source",
    }
}

#[cfg(feature = "standard-core")]
fn random_id() -> Result<String, DriverError> {
    random_bytes()
        .map(|bytes| format!("pair-{}", hex(&bytes[..8])))
        .map_err(|e| DriverError::Other(format!("pairing id generation failed: {e}")))
}

#[cfg(feature = "standard-core")]
fn random_secret() -> Result<String, DriverError> {
    random_bytes()
        .map(|bytes| hex(&bytes))
        .map_err(|e| DriverError::Other(format!("pairing secret generation failed: {e}")))
}

#[cfg(feature = "standard-core")]
fn random_bytes() -> Result<[u8; 32], getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(feature = "standard-core")]
fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "standard-core")]
fn hash_secret(secret: &str) -> String {
    let mut h = Hasher::new();
    h.update(b"andrias-external-pairing-secret-v1");
    h.update(secret.as_bytes());
    h.finalize().to_hex().to_string()
}

#[cfg(feature = "standard-core")]
fn display_checksum(secret: &str) -> String {
    hash_secret(secret).chars().take(8).collect()
}

#[cfg(feature = "standard-core")]
fn credential_hash(installation_id: &str, pairing_id: &str, generation: i64) -> String {
    let mut h = Hasher::new();
    h.update(b"andrias-external-credential-record-v1");
    h.update(installation_id.as_bytes());
    h.update(pairing_id.as_bytes());
    h.update(&generation.to_le_bytes());
    h.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use andrias_state::InMemoryBackend;
    use andrias_types::{EffectCapability, IdentityRef, ProcessId, Transport, TrustLevel};
    use anyhow::{Context, bail, ensure};
    use std::sync::Arc;

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn driver() -> (PairingDriver, Backend) {
        let state: Backend = Arc::new(InMemoryBackend::new());
        (PairingDriver::new(state.clone()), state)
    }

    fn expected_driver_error(
        result: Result<Outcome, DriverError>,
        label: &str,
    ) -> anyhow::Result<DriverError> {
        match result {
            Ok(outcome) => bail!("{label}: expected driver error, got {outcome:?}"),
            Err(error) => Ok(error),
        }
    }

    fn done_map(outcome: Outcome, label: &str) -> anyhow::Result<BTreeMap<String, Value>> {
        match outcome {
            Outcome::Done(Value::Map(record)) => Ok(record),
            other => bail!("{label}: expected map output, got {other:?}"),
        }
    }

    fn external_installation(id: &str, role: Role) -> anyhow::Result<Value> {
        let projection = match role {
            Role::Provider => {
                let provider_namespace = Path::try_new("effect")?
                    .try_push("external-provider")?
                    .try_push_literal(id)?;
                let search_effect = provider_namespace.clone().try_push("search")?.to_string();
                andrias_types::ExternalProjectionDef {
                    id: "provider".into(),
                    role,
                    namespace: Some(provider_namespace),
                    provides: vec![EffectCapability::new(search_effect, Purity::Idempotent)],
                    emits: None,
                    version: 1,
                }
            }
            Role::Source => andrias_types::ExternalProjectionDef {
                id: "source".into(),
                role,
                namespace: None,
                provides: vec![],
                emits: Some(andrias_types::EventSource {
                    sink: andrias_types::sandboxed_source_event_sink_path(id, "source")
                        .context("build source sink path")?,
                    purity: Purity::Effectful,
                    event_schema: None,
                    max_inline_payload_bytes: 65_536,
                    capacity: andrias_types::external::StreamCapacity {
                        max_events: 1024,
                        on_overflow: andrias_types::external::OverflowPolicy::DropOldest,
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
        Ok(serde_json::from_value(serde_json::to_value(def)?)?)
    }

    async fn install_external(state: &Backend, id: &str, role: Role) -> anyhow::Result<()> {
        let path = PairingDriver::installation_path(id).context("build installation state path")?;
        state
            .write_set(&path, external_installation(id, role)?)
            .await?;
        Ok(())
    }

    async fn lock_pairing_claim(
        state: &Backend,
        pairing_id: &str,
        requested_roles: &[&str],
        sas_verified: bool,
    ) -> anyhow::Result<()> {
        let path = PairingDriver::pairing_path(pairing_id).context("build pairing path")?;
        let mut record = state
            .read(&path)
            .await?
            .context("pairing record missing")?
            .as_map()
            .context("pairing record is not a map")?
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
        state.write_set(&path, Value::Map(record)).await?;
        Ok(())
    }

    #[test]
    fn pairing_state_paths_reject_path_delimiters() -> anyhow::Result<()> {
        ensure!(
            PairingDriver::pairing_path("pair/bad").is_err(),
            "pairing id with delimiter was accepted"
        );
        ensure!(
            PairingDriver::installation_path("ext/bad").is_err(),
            "installation id with delimiter was accepted"
        );
        ensure!(
            PairingDriver::session_path("ext", "provider/bad").is_err(),
            "role with delimiter was accepted"
        );
        ensure!(
            PairingDriver::manifest_path("platform/bad").is_err(),
            "manifest platform with delimiter was accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pairing_create_persists_hash_without_secret() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-1", Role::Provider).await?;
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
            .await?;
        let record = done_map(out, "create pairing")?;
        ensure!(
            record.get("state") == Some(&Value::Str(STATE_CREATED.into())),
            "unexpected pairing state: {:?}",
            record.get("state")
        );
        ensure!(
            !record.contains_key("pairing_secret"),
            "pairing record exposed secret"
        );
        let pairing_path =
            Path::parse("state://kernel/external-pairings/pair-1").context("parse pairing path")?;
        let stored = state
            .read(&pairing_path)
            .await?
            .context("pairing record missing")?;
        ensure!(
            stored == Value::Map(record),
            "stored pairing record did not match returned record"
        );

        let secret = driver
            .take_display_secret("pair-1")
            .context("display secret missing")?;
        ensure!(
            secret.len() == 64,
            "expected 64 hex chars, got {}",
            secret.len()
        );
        ensure!(
            secret.chars().all(|c| c.is_ascii_hexdigit()),
            "display secret was not hex"
        );
        ensure!(
            driver.take_display_secret("pair-1").is_none(),
            "display secret was readable more than once"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pairing_create_rejects_inline_secret() -> anyhow::Result<()> {
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
            .await?;
        ensure!(
            matches!(out, Outcome::Fail(Failure::InvalidInput { .. })),
            "unexpected inline secret outcome: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pairing_create_requires_installed_external_scope() -> anyhow::Result<()> {
        let (driver, _) = driver();
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-missing".into()));
        input.insert("installation_id".into(), Value::Str("missing-ext".into()));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(0),
                    Value::Map(input),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "create pairing without installation",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected missing installation error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pairing_create_rejects_unknown_identity_field() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-unknown-field", Role::Provider).await?;
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-unknown-field".into()));
        input.insert(
            "installation_id".into(),
            Value::Str("ext-unknown-field".into()),
        );
        input.insert("connection_id".into(), Value::Str("transport-conn".into()));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(0),
                    Value::Map(input),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "create pairing with unknown identity field",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected unknown identity field error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pairing_create_rejects_explicit_empty_allowed_roles() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-empty-role", Role::Provider).await?;
        let mut input = BTreeMap::new();
        input.insert("pairing_id".into(), Value::Str("pair-empty-role".into()));
        input.insert(
            "installation_id".into(),
            Value::Str("ext-empty-role".into()),
        );
        input.insert("allowed_roles".into(), Value::List(vec![]));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(0),
                    Value::Map(input),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "create pairing with empty allowed roles",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected empty allowed roles error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pairing_create_rejects_malformed_optional_fields() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-malformed-optional", Role::Provider).await?;
        for (field, value) in [
            ("pairing_id", Value::Int(1)),
            ("manifest_platform", Value::Int(1)),
            ("expires_at", Value::Str("never".into())),
            ("expires_at", Value::Int(-1)),
        ] {
            let mut input = BTreeMap::new();
            input.insert(
                "pairing_id".into(),
                Value::Str(format!("pair-malformed-{field}")),
            );
            input.insert(
                "installation_id".into(),
                Value::Str("ext-malformed-optional".into()),
            );
            input.insert(field.into(), value);
            let err = expected_driver_error(
                driver
                    .call(
                        MethodId::new(0),
                        Value::Map(input),
                        OutputMode::Unary,
                        &ctx(),
                    )
                    .await,
                "create pairing with malformed optional field",
            )?;
            ensure!(
                matches!(err, DriverError::Other(_)),
                "unexpected malformed optional field error: {err:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn approve_projects_provider_external_state() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-2", Role::Provider).await?;
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
            .await?;
        lock_pairing_claim(&state, "pair-2", &["provider"], true).await?;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-2".into()));
        driver
            .call(
                MethodId::new(1),
                Value::Map(approve),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        let session_path = Path::parse("state://kernel/external-sessions/ext-2/provider")
            .context("parse provider session path")?;
        let ext = state
            .read(&session_path)
            .await?
            .context("provider session missing")?;
        let m = ext.as_map().context("provider session is not a map")?;
        ensure!(
            m.get("state") == Some(&Value::Str("ready".into())),
            "unexpected provider session state: {:?}",
            m.get("state")
        );
        ensure!(
            m.get("credential_generation") == Some(&Value::Int(1)),
            "unexpected credential generation: {:?}",
            m.get("credential_generation")
        );
        Ok(())
    }

    #[tokio::test]
    async fn approve_rejects_malformed_persisted_security_fields() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-persisted-security", Role::Provider).await?;

        for (pairing_id, field, value) in [
            ("pair-missing-expiry", "expires_at", None),
            (
                "pair-bad-expiry",
                "expires_at",
                Some(Value::Str("never".into())),
            ),
            ("pair-missing-generation", "credential_generation", None),
            (
                "pair-bad-generation",
                "credential_generation",
                Some(Value::Str("0".into())),
            ),
        ] {
            let mut create = BTreeMap::new();
            create.insert("pairing_id".into(), Value::Str(pairing_id.into()));
            create.insert(
                "installation_id".into(),
                Value::Str("ext-persisted-security".into()),
            );
            driver
                .call(
                    MethodId::new(0),
                    Value::Map(create),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await?;
            lock_pairing_claim(&state, pairing_id, &["provider"], true).await?;

            let path = PairingDriver::pairing_path(pairing_id)
                .context("build pairing path for malformed record")?;
            let mut record = state
                .read(&path)
                .await?
                .context("pairing record missing")?
                .as_map()
                .context("pairing record is not a map")?
                .clone();
            match value {
                Some(value) => {
                    record.insert(field.into(), value);
                }
                None => {
                    record.remove(field);
                }
            }
            state.write_set(&path, Value::Map(record)).await?;

            let mut approve = BTreeMap::new();
            approve.insert("pairing_id".into(), Value::Str(pairing_id.into()));
            let err = expected_driver_error(
                driver
                    .call(
                        MethodId::new(1),
                        Value::Map(approve),
                        OutputMode::Unary,
                        &ctx(),
                    )
                    .await,
                "approve malformed persisted pairing record",
            )?;
            ensure!(
                matches!(err, DriverError::Other(_)),
                "unexpected malformed persisted record error: {err:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn terminal_operations_reject_malformed_pairing_state() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-bad-state", Role::Provider).await?;

        for (pairing_id, method_id) in [("pair-bad-deny", 2), ("pair-bad-replace", 3)] {
            let mut create = BTreeMap::new();
            create.insert("pairing_id".into(), Value::Str(pairing_id.into()));
            create.insert("installation_id".into(), Value::Str("ext-bad-state".into()));
            driver
                .call(
                    MethodId::new(0),
                    Value::Map(create),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await?;

            let path = PairingDriver::pairing_path(pairing_id)
                .context("build pairing path for malformed state")?;
            let mut record = state
                .read(&path)
                .await?
                .context("pairing record missing")?
                .as_map()
                .context("pairing record is not a map")?
                .clone();
            record.remove("state");
            state.write_set(&path, Value::Map(record)).await?;

            let mut input = BTreeMap::new();
            input.insert("pairing_id".into(), Value::Str(pairing_id.into()));
            let err = expected_driver_error(
                driver
                    .call(
                        MethodId::new(method_id),
                        Value::Map(input),
                        OutputMode::Unary,
                        &ctx(),
                    )
                    .await,
                "terminal operation with malformed pairing state",
            )?;
            ensure!(
                matches!(err, DriverError::Other(_)),
                "unexpected malformed state error: {err:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn pairing_scope_can_come_from_multi_projection_installation() -> anyhow::Result<()> {
        let (driver, state) = driver();
        let install = andrias_types::ExternalInstallationDef {
            id: "instant_messaging_platform".into(),
            platform: "instant_messaging_platform".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![
                andrias_types::ExternalProjectionDef {
                    id: "source".into(),
                    role: Role::Source,
                    namespace: None,
                    provides: vec![],
                    emits: Some(andrias_types::EventSource {
                        sink: andrias_types::sandboxed_source_event_sink_path(
                            "instant_messaging_platform",
                            "source",
                        )
                        .context("build source sink path")?,
                        purity: Purity::Effectful,
                        event_schema: None,
                        max_inline_payload_bytes: 65_536,
                        capacity: andrias_types::external::StreamCapacity {
                            max_events: 1024,
                            on_overflow: andrias_types::external::OverflowPolicy::DropOldest,
                        },
                        rate_limit: None,
                        commands: false,
                        command_schema: None,
                        command_result_schema: None,
                    }),
                    version: 1,
                },
                andrias_types::ExternalProjectionDef {
                    id: "provider".into(),
                    role: Role::Provider,
                    namespace: Some(
                        Path::parse("effect://external-provider/instant_messaging_platform")
                            .context("parse provider namespace")?,
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
        let installation_path =
            Path::parse("state://kernel/external-installations/instant_messaging_platform")
                .context("parse installation path")?;
        state
            .write_set(
                &installation_path,
                serde_json::from_value(serde_json::to_value(install)?)?,
            )
            .await?;

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
            .await?;
        lock_pairing_claim(
            &state,
            "pair-instant_messaging_platform",
            &["source", "provider"],
            true,
        )
        .await?;
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
            .await?;
        let source_path =
            Path::parse("state://kernel/external-sessions/instant_messaging_platform/source")
                .context("parse source session path")?;
        ensure!(
            state.read(&source_path).await?.is_some(),
            "source session missing"
        );
        let provider_path =
            Path::parse("state://kernel/external-sessions/instant_messaging_platform/provider")
                .context("parse provider session path")?;
        ensure!(
            state.read(&provider_path).await?.is_some(),
            "provider session missing"
        );
        Ok(())
    }

    #[tokio::test]
    async fn approve_requires_sas_verified() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-sas", Role::Provider).await?;
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
            .await?;
        lock_pairing_claim(&state, "pair-sas", &["provider"], false).await?;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-sas".into()));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(1),
                    Value::Map(approve),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "approve without sas verification",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected sas verification error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn approve_rejects_frontend_claim_fields() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-claim", Role::Provider).await?;
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
            .await?;
        lock_pairing_claim(&state, "pair-claim", &["provider"], true).await?;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-claim".into()));
        approve.insert("sas_verified".into(), Value::Bool(true));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(1),
                    Value::Map(approve),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "approve with frontend claim fields",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected frontend claim error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn approve_rejects_roles_outside_allowed_set() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-role", Role::Provider).await?;
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
            .await?;
        lock_pairing_claim(&state, "pair-role", &["source"], true).await?;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-role".into()));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(1),
                    Value::Map(approve),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "approve roles outside allowed set",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected role claim error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn approve_terminalizes_expired_intent() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-exp", Role::Provider).await?;
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
            .await?;
        let mut approve = BTreeMap::new();
        approve.insert("pairing_id".into(), Value::Str("pair-exp".into()));
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(1),
                    Value::Map(approve),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "approve expired intent",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected expired intent error: {err:?}"
        );
        let pairing_path = Path::parse("state://kernel/external-pairings/pair-exp")
            .context("parse expired pairing path")?;
        let stored = state
            .read(&pairing_path)
            .await?
            .context("expired pairing record missing")?;
        let state = stored
            .as_map()
            .context("expired pairing record is not a map")?
            .get("state");
        ensure!(
            state == Some(&Value::Str(STATE_EXPIRED.into())),
            "expired pairing state was not terminalized"
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_terminalizes_old_intent_and_creates_new_one() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-3", Role::Provider).await?;
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
            .await?;
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
            .await?;
        let old_path = Path::parse("state://kernel/external-pairings/pair-3")
            .context("parse old pairing path")?;
        let old = state
            .read(&old_path)
            .await?
            .context("old pairing record missing")?;
        let pairing_state = old
            .as_map()
            .context("old pairing record is not a map")?
            .get("state");
        ensure!(
            pairing_state == Some(&Value::Str(STATE_REPLACED.into())),
            "old pairing was not replaced"
        );
        let new_path = Path::parse("state://kernel/external-pairings/pair-3b")
            .context("parse replacement pairing path")?;
        let new = state
            .read(&new_path)
            .await?
            .context("replacement pairing record missing")?;
        let pairing_state = new
            .as_map()
            .context("replacement pairing record is not a map")?
            .get("state");
        ensure!(
            pairing_state == Some(&Value::Str(STATE_CREATED.into())),
            "replacement pairing was not created"
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_validation_failure_leaves_old_intent_created() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-replace-validate", Role::Provider).await?;
        let mut create = BTreeMap::new();
        create.insert(
            "pairing_id".into(),
            Value::Str("pair-replace-validate".into()),
        );
        create.insert(
            "installation_id".into(),
            Value::Str("ext-replace-validate".into()),
        );
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;

        for (replacement_id, expires_at) in [
            ("pair-replace-validate-b", Value::Str("never".into())),
            ("pair/replace/bad", Value::Int(0)),
        ] {
            let mut replace = BTreeMap::new();
            replace.insert(
                "pairing_id".into(),
                Value::Str("pair-replace-validate".into()),
            );
            replace.insert(
                "replacement_pairing_id".into(),
                Value::Str(replacement_id.into()),
            );
            replace.insert("expires_at".into(), expires_at);
            let err = expected_driver_error(
                driver
                    .call(
                        MethodId::new(3),
                        Value::Map(replace),
                        OutputMode::Unary,
                        &ctx(),
                    )
                    .await,
                "replace with malformed input",
            )?;
            ensure!(
                matches!(err, DriverError::Other(_)),
                "unexpected malformed replace error: {err:?}"
            );

            let old = state
                .read(&PairingDriver::pairing_path("pair-replace-validate")?)
                .await?
                .context("old pairing record missing")?;
            let old_state = old
                .as_map()
                .context("old pairing record is not a map")?
                .get("state");
            ensure!(
                old_state == Some(&Value::Str(STATE_CREATED.into())),
                "old pairing was mutated before replace validation finished"
            );
            ensure!(
                driver.take_display_secret(replacement_id).is_none(),
                "replace staged a display secret after validation failure"
            );
        }
        ensure!(
            state
                .read(&PairingDriver::pairing_path("pair-replace-validate-b")?)
                .await?
                .is_none(),
            "replacement record was written after validation failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_rejects_missing_stored_allowed_roles() -> anyhow::Result<()> {
        let (driver, state) = driver();
        install_external(&state, "ext-replace-roles", Role::Provider).await?;
        let mut create = BTreeMap::new();
        create.insert("pairing_id".into(), Value::Str("pair-replace-roles".into()));
        create.insert(
            "installation_id".into(),
            Value::Str("ext-replace-roles".into()),
        );
        driver
            .call(
                MethodId::new(0),
                Value::Map(create),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;

        let path = PairingDriver::pairing_path("pair-replace-roles")?;
        let mut record = state
            .read(&path)
            .await?
            .context("pairing record missing")?
            .as_map()
            .context("pairing record is not a map")?
            .clone();
        record.remove("allowed_roles");
        state.write_set(&path, Value::Map(record)).await?;

        let mut replace = BTreeMap::new();
        replace.insert("pairing_id".into(), Value::Str("pair-replace-roles".into()));
        replace.insert(
            "replacement_pairing_id".into(),
            Value::Str("pair-replace-roles-b".into()),
        );
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(3),
                    Value::Map(replace),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "replace with missing stored allowed roles",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected missing allowed_roles error: {err:?}"
        );
        let old = state
            .read(&path)
            .await?
            .context("old pairing record missing")?;
        let old_state = old
            .as_map()
            .context("old pairing record is not a map")?
            .get("state");
        ensure!(
            old_state == Some(&Value::Str(STATE_CREATED.into())),
            "old pairing was replaced despite malformed stored allowed_roles"
        );
        ensure!(
            state
                .read(&PairingDriver::pairing_path("pair-replace-roles-b")?)
                .await?
                .is_none(),
            "replacement record was created from malformed stored allowed_roles"
        );

        let mut replace_with_explicit_roles = BTreeMap::new();
        replace_with_explicit_roles
            .insert("pairing_id".into(), Value::Str("pair-replace-roles".into()));
        replace_with_explicit_roles.insert(
            "replacement_pairing_id".into(),
            Value::Str("pair-replace-roles-c".into()),
        );
        replace_with_explicit_roles.insert(
            "allowed_roles".into(),
            Value::List(vec![Value::Str("provider".into())]),
        );
        let err = expected_driver_error(
            driver
                .call(
                    MethodId::new(3),
                    Value::Map(replace_with_explicit_roles),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await,
            "replace with explicit roles and missing stored allowed roles",
        )?;
        ensure!(
            matches!(err, DriverError::Other(_)),
            "unexpected explicit roles missing allowed_roles error: {err:?}"
        );
        ensure!(
            state
                .read(&PairingDriver::pairing_path("pair-replace-roles-c")?)
                .await?
                .is_none(),
            "replacement with explicit roles was created from malformed stored allowed_roles"
        );
        Ok(())
    }

    #[tokio::test]
    async fn revoke_writes_generation_floor() -> anyhow::Result<()> {
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
            .await?;
        let revoke_path = Path::parse("state://kernel/external-credential-revocations/ext-4")
            .context("parse revocation path")?;
        let revoked = state
            .read(&revoke_path)
            .await?
            .context("revocation record missing")?;
        let m = revoked.as_map().context("revocation record is not a map")?;
        ensure!(
            m.get("state") == Some(&Value::Str(STATE_REVOKED.into())),
            "unexpected revocation state: {:?}",
            m.get("state")
        );
        ensure!(
            m.get("credential_generation_floor") == Some(&Value::Int(7)),
            "unexpected generation floor: {:?}",
            m.get("credential_generation_floor")
        );
        Ok(())
    }

    #[tokio::test]
    async fn revoke_rejects_invalid_generation_floor() -> anyhow::Result<()> {
        for floor in [Value::Int(0), Value::Int(-1), Value::Str("7".into())] {
            let (driver, state) = driver();
            let mut input = BTreeMap::new();
            input.insert(
                "installation_id".into(),
                Value::Str("ext-invalid-floor".into()),
            );
            input.insert("credential_generation_floor".into(), floor);

            let err = match driver
                .call(
                    MethodId::new(4),
                    Value::Map(input),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await
            {
                Ok(_) => bail!("revoke accepted invalid generation floor"),
                Err(err) => err,
            };
            ensure!(
                matches!(err, DriverError::Other(_)),
                "unexpected revoke error: {err:?}"
            );
            let path =
                Path::parse("state://kernel/external-credential-revocations/ext-invalid-floor")
                    .context("parse revoke path")?;
            let stored = state.read(&path).await.context("read revoke path")?;
            ensure!(stored.is_none(), "invalid revoke wrote state: {stored:?}");
        }
        Ok(())
    }
}
