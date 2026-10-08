//! Pairing request admission and stored-intent invariants.

use xolotl_kernel::DriverError;
use xolotl_types::{ExternalInstallationDef, Failure, Outcome, Role, Value, ValueMap, ValueView};

#[cfg(feature = "standard-core")]
pub(super) const STATE_CREATED: &str = "created";
#[cfg(feature = "standard-core")]
pub(super) const STATE_APPROVED: &str = "approved";
#[cfg(feature = "standard-core")]
pub(super) const STATE_DENIED: &str = "denied";
#[cfg(feature = "standard-core")]
pub(super) const STATE_EXPIRED: &str = "expired";
#[cfg(feature = "standard-core")]
pub(super) const STATE_REVOKED: &str = "revoked";

#[derive(Clone, Debug)]
#[cfg(feature = "standard-core")]
pub(super) struct PairingScope {
    pub(super) roles: Vec<String>,
    pub(super) installation_epoch: u64,
}

#[cfg(feature = "standard-core")]
pub(super) fn requested_credential_generation_floor(
    m: &ValueMap,
) -> Result<Option<u64>, DriverError> {
    match m.get("credential_generation_floor").map(Value::view) {
        None => Ok(None),
        Some(ValueView::Int(floor)) if floor >= 1 => Ok(Some(floor as u64)),
        Some(ValueView::Int(_)) => Err(DriverError::Other(
            "credential_generation_floor must be at least 1".into(),
        )),
        Some(_) => Err(DriverError::Other(
            "credential_generation_floor must be an integer".into(),
        )),
    }
}

#[cfg(feature = "standard-core")]
pub(super) fn field_str<'a>(m: &'a ValueMap, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Value::as_str)
}

#[cfg(feature = "standard-core")]
fn record_optional_str<'a>(
    record: &'a ValueMap,
    key: &str,
) -> Result<Option<&'a str>, DriverError> {
    match record.get(key).map(Value::view) {
        None => Ok(None),
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(Some(value)),
        Some(ValueView::Str(_)) => Err(DriverError::Other(format!(
            "pairing record field {key} must not be empty"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "pairing record field {key} must be a string"
        ))),
    }
}

#[cfg(feature = "standard-core")]
pub(super) fn record_required_str<'a>(
    record: &'a ValueMap,
    key: &str,
) -> Result<&'a str, DriverError> {
    record_optional_str(record, key)?
        .ok_or_else(|| DriverError::Other(format!("pairing record missing {key}")))
}

#[cfg(feature = "standard-core")]
fn optional_str<'a>(m: &'a ValueMap, key: &str) -> Result<Option<&'a str>, DriverError> {
    match m.get(key).map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(Some(value)),
        Some(ValueView::Str(_)) => Err(DriverError::Other(format!("{key} must not be empty"))),
        Some(_) => Err(DriverError::Other(format!("{key} must be a string"))),
    }
}

#[cfg(feature = "standard-core")]
pub(super) fn required_str<'a>(m: &'a ValueMap, key: &str) -> Result<&'a str, DriverError> {
    optional_str(m, key)?.ok_or_else(|| DriverError::Other(format!("{key} is required")))
}

#[cfg(feature = "standard-core")]
pub(super) fn optional_nonnegative_int(
    m: &ValueMap,
    key: &str,
    default: i64,
) -> Result<i64, DriverError> {
    match m.get(key).map(Value::view) {
        Some(ValueView::Null) | None => Ok(default),
        Some(ValueView::Int(value)) if value >= 0 => Ok(value),
        Some(ValueView::Int(_)) => Err(DriverError::Other(format!("{key} must be nonnegative"))),
        Some(_) => Err(DriverError::Other(format!("{key} must be an integer"))),
    }
}

#[cfg(feature = "standard-core")]
pub(super) fn required_record_nonnegative_int(
    record: &ValueMap,
    key: &str,
) -> Result<i64, DriverError> {
    match record.get(key).map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => Ok(value),
        Some(ValueView::Int(_)) => Err(DriverError::Other(format!(
            "pairing record field {key} must be nonnegative"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "pairing record field {key} must be an integer"
        ))),
        None => Err(DriverError::Other(format!("pairing record missing {key}"))),
    }
}

#[cfg(feature = "standard-core")]
pub(super) fn ensure_installation_epoch(
    record: &ValueMap,
    scope: &PairingScope,
) -> Result<(), DriverError> {
    let stored = record_required_str(record, "installation_epoch")?
        .parse::<u64>()
        .map_err(|error| {
            DriverError::Other(format!(
                "pairing record has invalid installation_epoch: {error}"
            ))
        })?;
    if stored != scope.installation_epoch {
        return Err(DriverError::Other(
            "pairing intent belongs to a retired or replaced installation".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
pub(super) fn validate_id_segment(id: &str, label: &str) -> Result<(), DriverError> {
    if !xolotl_types::path::is_simple_id_segment(id) {
        return Err(DriverError::Other(format!(
            "{label} must start with an ASCII letter or digit and contain only ASCII letters, digits, '_' or '-'"
        )));
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
pub(super) fn string_list(values: Vec<String>) -> Value {
    Value::list(values.into_iter().map(Value::string).collect())
}

#[cfg(feature = "standard-core")]
pub(super) fn role_values(v: Option<&Value>, field: &str) -> Result<Vec<String>, DriverError> {
    let roles = match v.map(Value::view) {
        None => Vec::new(),
        Some(ValueView::Str(s)) => vec![s.to_owned()],
        Some(ValueView::List(items)) => {
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
pub(super) fn ensure_not_terminal(record: &ValueMap) -> Result<(), DriverError> {
    match field_str(record, "state") {
        Some(STATE_CREATED) => Ok(()),
        Some(STATE_APPROVED | STATE_DENIED | STATE_EXPIRED | STATE_REVOKED) => {
            Err(DriverError::Other("pairing intent is terminal".into()))
        }
        Some(state) => Err(DriverError::Other(format!(
            "pairing intent has unknown state {state:?}"
        ))),
        None => Err(DriverError::Other("pairing intent has no state".into())),
    }
}

#[cfg(feature = "standard-core")]
pub(super) fn ensure_created(record: &ValueMap) -> Result<(), DriverError> {
    match field_str(record, "state") {
        Some(STATE_CREATED) => Ok(()),
        Some(state) => Err(DriverError::Other(format!(
            "pairing intent is not approvable in state {state:?}"
        ))),
        None => Err(DriverError::Other("pairing intent has no state".into())),
    }
}

#[cfg(feature = "standard-core")]
pub(super) fn is_expired(record: &ValueMap) -> Result<bool, DriverError> {
    let expires_at = required_record_nonnegative_int(record, "expires_at")?;
    Ok(expires_at > 0 && expires_at <= xolotl_kernel::host::system_now_millis())
}

#[cfg(feature = "standard-core")]
pub(super) fn ensure_record_sas_verified(record: &ValueMap) -> Result<(), DriverError> {
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
pub(super) fn ensure_roles_allowed(
    roles: &[String],
    allowed: &[String],
) -> Result<(), DriverError> {
    if roles.is_empty() {
        return Err(DriverError::Other(
            "approve requires at least one role".into(),
        ));
    }
    for role in roles {
        if Role::from_slug(role).is_none() {
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
pub(super) fn reject_inline_secret(m: &ValueMap) -> Option<Outcome> {
    if m.get("pairing_secret").is_some() {
        return Some(Outcome::Fail(Failure::InvalidInput {
            reason: "pairing_secret must be generated by PairingDriver and exposed only through the display edge".into(),
        }));
    }
    None
}

#[cfg(feature = "standard-core")]
pub(super) fn admit_pairing_input(
    input: &Value,
) -> Result<(), Box<xolotl_kernel::driver::InputRejection>> {
    let Some(fields) = input.as_map() else {
        return Ok(());
    };
    let Some(Outcome::Fail(failure)) = reject_inline_secret(fields) else {
        return Ok(());
    };
    let recorded_input = Value::map(
        fields
            .iter()
            .map(|(key, value)| {
                let value = if key == "pairing_secret" {
                    Value::string("<redacted>".into())
                } else {
                    value.clone()
                };
                (key.to_owned(), value)
            })
            .collect(),
    );
    Err(Box::new(xolotl_kernel::driver::InputRejection {
        failure,
        recorded_input,
    }))
}

#[cfg(feature = "standard-core")]
pub(super) fn reject_unknown_fields(
    m: &ValueMap,
    method: &str,
    allowed: &[&str],
) -> Result<(), DriverError> {
    for key in m.keys() {
        if !allowed.contains(&key) {
            return Err(DriverError::Other(format!(
                "{method} does not accept field {key:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
pub(super) fn reject_inline_install_fields(m: &ValueMap, method: &str) -> Result<(), DriverError> {
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
        if m.get(key).is_some() {
            return Err(DriverError::Other(format!(
                "{method} must reference an installed ExternalInstallationDef; field {key:?} is not accepted"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
pub(super) fn reject_pairing_claim_fields(m: &ValueMap, method: &str) -> Result<(), DriverError> {
    for key in [
        "sas_verified",
        "requested_roles",
        "roles",
        "approved_roles",
        "claim",
        "registry_hash",
    ] {
        if m.get(key).is_some() {
            return Err(DriverError::Other(format!(
                "{method} must not carry locked pairing claim field {key:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
pub(super) fn reject_approve_claim_fields(m: &ValueMap) -> Result<(), DriverError> {
    reject_inline_install_fields(m, "pairing.approve")?;
    for key in [
        "sas_verified",
        "requested_roles",
        "roles",
        "allowed_roles",
        "installation_id",
        "claim",
        "registry_hash",
    ] {
        if m.get(key).is_some() {
            return Err(DriverError::Other(format!(
                "pairing.approve must consume locked record claims; field {key:?} is not accepted"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "standard-core")]
pub(super) fn installation_roles(
    def: &ExternalInstallationDef,
) -> Result<Vec<String>, DriverError> {
    let mut roles = Vec::new();
    for projection in &def.projections {
        let role = projection.role.as_str().to_string();
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
