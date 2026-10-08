//! Account grant compilation and management authorization policy.

use super::{
    AuthError, ConsolePrincipal, ROOT_USERNAME, UserRecord, local_identity_path,
    optional_bool_field, optional_string_list_field, random_token, read_user, validate_username,
};
use crate::paths::role_path;
use std::collections::HashSet;
use xolotl_kernel::{Bootstrap, CompiledRequestGrantTemplate};
use xolotl_state::Backend;
use xolotl_types::{
    CapSet, Capability, GrantMethods, GrantRights, Path, ResourceName, ResourceSelector,
    RightFlags, Value,
};

/// Compile all matching account grants for one concrete request target. The
/// caller has no operation input yet, so each predicate is preserved on its
/// request selector for the kernel's per-operation residual check.
pub(crate) fn compile_principal_request_grants(
    boot: &Bootstrap,
    principal: &ConsolePrincipal,
    target: &ResourceName,
    verb: &str,
    method: &str,
    selector: ResourceSelector,
) -> Result<Vec<CompiledRequestGrantTemplate>, AuthError> {
    let selectors = principal_request_selectors_for_method(
        boot,
        principal,
        target.path(),
        verb,
        Some(method),
        selector,
    )?;
    let registry = boot.kernel().registry();
    let resource = registry
        .resolve_resource(target)
        .map_err(|error| AuthError::State(error.to_string()))?;
    let (_, installed) = registry
        .resource_method(resource, method)
        .ok_or_else(|| AuthError::State("resource method contract unavailable".into()))?;
    if installed.authority.verb() != verb {
        return Err(AuthError::PermissionDenied);
    }
    let methods = GrantMethods::name(installed.name);
    Ok(selectors
        .into_iter()
        .map(|selector| CompiledRequestGrantTemplate {
            selector,
            rights: GrantRights::new(methods.clone(), RightFlags::empty()),
        })
        .collect())
}

/// Compile the caller's propagation authority into flag-only kernel grants.
/// Kernel selectors bind the opened method category; the Console's separate
/// `spawn-with` capability supplies only predicates and the propagation bit.
pub(crate) fn compile_principal_propagation_grants(
    boot: &Bootstrap,
    principal: &ConsolePrincipal,
    target: &Path,
    method_verb: &str,
    method: &str,
    mut method_selector: ResourceSelector,
) -> Result<Vec<CompiledRequestGrantTemplate>, AuthError> {
    method_selector.pattern.verb = "spawn-with".into();
    let selectors = principal_request_selectors_for_method(
        boot,
        principal,
        target,
        "spawn-with",
        Some(method),
        method_selector,
    )?;
    Ok(selectors
        .into_iter()
        .map(|mut selector| {
            selector.pattern.verb = method_verb.into();
            CompiledRequestGrantTemplate {
                selector,
                rights: GrantRights::new(GrantMethods::none(), RightFlags::SPAWN_WITH),
            }
        })
        .collect())
}

pub(crate) fn principal_request_selectors(
    boot: &Bootstrap,
    principal: &ConsolePrincipal,
    target: &Path,
    verb: &str,
    selector: ResourceSelector,
) -> Result<Vec<ResourceSelector>, AuthError> {
    principal_request_selectors_for_method(boot, principal, target, verb, None, selector)
}

fn principal_request_selectors_for_method(
    boot: &Bootstrap,
    principal: &ConsolePrincipal,
    target: &Path,
    verb: &str,
    method: Option<&str>,
    selector: ResourceSelector,
) -> Result<Vec<ResourceSelector>, AuthError> {
    const MAX_ALTERNATIVES: usize = 1024;
    if !selector.matches(verb, target) || selector.pattern.predicate.is_some() {
        return Err(AuthError::PermissionDenied);
    }
    let now = boot.kernel().host_runtime().now_millis();
    let mut selectors = Vec::new();
    let mut seen_predicates = HashSet::new();
    for capability in principal.grants.iter() {
        let matches = match method {
            Some(method) => capability.matches_method_preflight(verb, target, method, now),
            None => capability.matches_preflight(verb, target, now),
        };
        if !matches {
            continue;
        }
        let Some(predicate) = capability.predicate.as_ref() else {
            // This single grant dominates every conditional alternative.
            return Ok(vec![selector]);
        };
        if !seen_predicates.insert(predicate) {
            continue;
        }
        if selectors.len() >= MAX_ALTERNATIVES {
            return Err(AuthError::PermissionDenied);
        }
        let mut candidate = selector.clone();
        candidate.pattern.predicate = capability.predicate.clone();
        selectors.push(candidate);
    }
    if selectors.is_empty() {
        Err(AuthError::PermissionDenied)
    } else {
        Ok(selectors)
    }
}

/// Supply server-owned account provenance and an instance-bound Kernel identity.
pub(crate) fn prepare_user_config(
    path: &Path,
    current: Option<&Value>,
    value: &mut Value,
    principal: &ConsolePrincipal,
    now: i64,
) -> Result<(), AuthError> {
    if !crate::paths::is_user_record_path(path) {
        return Ok(());
    }
    if current.is_none()
        && path
            .segments()
            .last()
            .is_some_and(|name| name == ROOT_USERNAME)
    {
        // Only bootstrap may install the reserved recovery account.
        return Err(AuthError::PermissionDenied);
    }
    let mut map = value
        .as_map()
        .cloned()
        .ok_or(AuthError::InvalidCredentialRequest)?;
    let protected = [
        "account_id",
        "bootstrap_owner",
        "identity_path",
        "created_by",
        "created_at",
    ];
    if let Some(current) = current {
        let previous = current
            .as_map()
            .ok_or(AuthError::InvalidCredentialRequest)?;
        for field in protected {
            let stored = previous
                .get(field)
                .ok_or(AuthError::InvalidCredentialRequest)?;
            if map.get(field).is_some_and(|proposed| proposed != stored) {
                return Err(AuthError::InvalidCredentialRequest);
            }
            map.insert(field.into(), stored.clone())
                .map_err(|_error| AuthError::InvalidCredentialRequest)?;
        }
    } else {
        if protected.iter().any(|field| map.contains_key(field)) {
            return Err(AuthError::InvalidCredentialRequest);
        }
        let account_id = random_token(18)?;
        map.insert("account_id".into(), Value::string(account_id.clone()))
            .map_err(|_error| AuthError::InvalidCredentialRequest)?;
        map.insert("bootstrap_owner".into(), Value::boolean(false))
            .map_err(|_error| AuthError::InvalidCredentialRequest)?;
        map.insert(
            "identity_path".into(),
            Value::string(local_identity_path(&account_id)?),
        )
        .map_err(|_error| AuthError::InvalidCredentialRequest)?;
        map.insert(
            "created_by".into(),
            Value::string(format!("local:{}", principal.account_id)),
        )
        .map_err(|_error| AuthError::InvalidCredentialRequest)?;
        map.insert("created_at".into(), Value::integer(now))
            .map_err(|_error| AuthError::InvalidCredentialRequest)?;
    }
    *value = Value::from(map);
    Ok(())
}

/// Authorize a principal for a state path and optional replacement value.
///
/// Console management paths require both direct path authority and the console
/// management effect authority; user/role writes are additionally checked so a
/// non-root admin cannot grant authority above their ceiling.
pub(crate) async fn authorize_path(
    state: &Backend,
    principal: &ConsolePrincipal,
    verb: &str,
    path: &Path,
    new_value: Option<&Value>,
) -> Result<(), AuthError> {
    if !principal.grants.contains(verb, path) {
        return Err(AuthError::PermissionDenied);
    }
    if crate::paths::is_console_descendant(path) {
        let user_mgmt = Path::parse(crate::paths::MANAGE_USERS_EFFECT)?;
        if !principal.grants.contains("perform", &user_mgmt) {
            return Err(AuthError::PermissionDenied);
        }
    }
    if verb == "write" && crate::paths::is_user_descendant(path) {
        authorize_user_target(state, principal, path, new_value).await?;
    }
    if verb == "write" && crate::paths::is_role_descendant(path) {
        authorize_role_target(state, principal, path, new_value).await?;
    }
    Ok(())
}

/// Authorize a prefix scan only when one unconditional grant covers every
/// possible row below the prefix. A state cursor can contain the last scanned
/// path, including a row that did not fit in the response, so filtering rows
/// after the query cannot safely attenuate a narrower grant.
pub(crate) async fn authorize_prefix_read(
    state: &Backend,
    principal: &ConsolePrincipal,
    prefix: &Path,
) -> Result<(), AuthError> {
    if !prefix.is_concrete() {
        return Err(AuthError::PermissionDenied);
    }
    let subtree = Capability::try_new(
        "read",
        prefix.scheme(),
        prefix
            .segments()
            .iter()
            .map(|segment| segment.as_str())
            .chain(std::iter::once("**")),
        None,
    )
    .map_err(|_error| AuthError::PermissionDenied)?;
    let subtree = match prefix.cluster() {
        Some(cluster) => subtree
            .try_with_cluster(cluster)
            .map_err(|_error| AuthError::PermissionDenied)?,
        None => subtree,
    };
    if !principal
        .grants
        .iter()
        .any(|grant| grant.predicate.is_none() && grant.covers_cap(&subtree))
    {
        return Err(AuthError::PermissionDenied);
    }
    authorize_path(state, principal, "read", prefix, None).await
}

async fn authorize_user_target(
    state: &Backend,
    principal: &ConsolePrincipal,
    path: &Path,
    new_value: Option<&Value>,
) -> Result<(), AuthError> {
    let Some(username) = path.segments().last().map(|s| s.to_string()) else {
        return Err(AuthError::PermissionDenied);
    };
    validate_username(&username)?;

    if let Some(existing) = read_user(state, &username).await? {
        if existing.bootstrap_owner && !is_bootstrap_owner(state, principal).await? {
            return Err(AuthError::PermissionDenied);
        }
        let target = effective_grants(state, &existing).await?;
        if !capset_covers(&principal.grants, &target) {
            return Err(AuthError::PermissionDenied);
        }
    }
    if let Some(value) = new_value {
        let candidate = UserRecord::from_value(&username, value)?;
        let candidate_ceiling = capset_from_strings(&candidate.authority_ceiling)?;
        let candidate_effective = effective_grants(state, &candidate).await?;
        if !capset_covers(&principal.grants, &candidate_ceiling)
            || !capset_covers(&principal.grants, &candidate_effective)
        {
            return Err(AuthError::PermissionDenied);
        }
        if username == ROOT_USERNAME && candidate.bootstrap_owner {
            enforce_root_invariants(&candidate, &candidate_effective)?;
        }
    }
    Ok(())
}

async fn authorize_role_target(
    state: &Backend,
    principal: &ConsolePrincipal,
    path: &Path,
    new_value: Option<&Value>,
) -> Result<(), AuthError> {
    let Some(role) = path.segments().last().map(|s| s.to_string()) else {
        return Err(AuthError::PermissionDenied);
    };
    validate_username(&role)?;

    let role_path = role_path(&role)?;
    if let Some(existing) = state.read(&role_path).await? {
        let existing_grants = capset_from_strings(&role_grants(&existing)?)?;
        if !capset_covers(&principal.grants, &existing_grants) {
            return Err(AuthError::PermissionDenied);
        }
        if role_frozen(&existing)? && !is_bootstrap_owner(state, principal).await? {
            return Err(AuthError::PermissionDenied);
        }
    }

    if let Some(value) = new_value {
        let candidate_grants = capset_from_strings(&role_grants(value)?)?;
        if !capset_covers(&principal.grants, &candidate_grants) {
            return Err(AuthError::PermissionDenied);
        }
        if role_frozen(value)? && !is_bootstrap_owner(state, principal).await? {
            return Err(AuthError::PermissionDenied);
        }
    }
    Ok(())
}

async fn is_bootstrap_owner(
    state: &Backend,
    principal: &ConsolePrincipal,
) -> Result<bool, AuthError> {
    Ok(read_user(state, ROOT_USERNAME)
        .await?
        .is_some_and(|root| root.bootstrap_owner && root.account_key() == principal.account_key()))
}

fn enforce_root_invariants(user: &UserRecord, effective: &CapSet) -> Result<(), AuthError> {
    if !matches!(user.status.as_str(), "active") {
        return Err(AuthError::PermissionDenied);
    }
    let user_mgmt = Path::parse(crate::paths::MANAGE_USERS_EFFECT)?;
    let root_user = crate::paths::user_path(ROOT_USERNAME)?;
    if !effective.contains("perform", &user_mgmt) || !effective.contains("write", &root_user) {
        return Err(AuthError::PermissionDenied);
    }
    Ok(())
}

pub(super) fn capset_covers(parent: &CapSet, child: &CapSet) -> bool {
    child.iter().all(|c| parent.iter().any(|p| p.covers_cap(c)))
}

/// Restrict current account grants to the session's original authority.
/// `CapSet::intersect` is directional attenuation, so it cannot express a
/// newly conditional account grant under an unconditional session ceiling.
/// Keep only intersections whose entire path pattern can be proved to be a
/// subset of both inputs; incomparable paths or predicates fail closed.
pub(super) fn effective_session_grants(
    current: &CapSet,
    ceiling: &CapSet,
) -> Result<CapSet, AuthError> {
    const MAX_EFFECTIVE_GRANTS: usize = 1024;
    if current == ceiling {
        if current.len() > MAX_EFFECTIVE_GRANTS {
            return Err(AuthError::State(
                "effective session grants exceed limit".into(),
            ));
        }
        return Ok(current.clone());
    }
    let mut effective = CapSet::new();
    let mut seen = HashSet::new();
    for grant in current.iter() {
        for limit in ceiling.iter() {
            if grant.predicate.is_some()
                && limit.predicate.is_some()
                && grant.predicate != limit.predicate
            {
                continue;
            }
            let narrower = if grant.covers_cap_path_pattern(limit) {
                limit
            } else if limit.covers_cap_path_pattern(grant) {
                grant
            } else {
                continue;
            };
            let method = match (grant.method.as_deref(), limit.method.as_deref()) {
                (Some(left), Some(right)) if left != right => continue,
                (Some(left), _) => Some(left),
                (_, Some(right)) => Some(right),
                (None, None) => None,
            };
            let mut candidate = narrower.clone();
            candidate.method = method.map(str::to_string);
            if candidate.predicate.is_none() {
                candidate.predicate = grant
                    .predicate
                    .as_ref()
                    .or(limit.predicate.as_ref())
                    .cloned();
            }
            if seen.contains(&candidate) {
                continue;
            }
            if effective.len() >= MAX_EFFECTIVE_GRANTS {
                return Err(AuthError::State(
                    "effective session grants exceed limit".into(),
                ));
            }
            seen.insert(candidate.clone());
            effective.push(candidate);
        }
    }
    Ok(effective)
}

pub(super) async fn effective_grants(
    state: &Backend,
    user: &UserRecord,
) -> Result<CapSet, AuthError> {
    let mut grants = user.grants.clone();
    for role in &user.roles {
        let role_path = role_path(role)?;
        if let Some(v) = state.read(&role_path).await? {
            grants.extend(role_grants(&v)?);
        }
    }
    let requested = capset_from_strings(&grants)?;
    let ceiling = capset_from_strings(&user.authority_ceiling)?;
    Ok(ceiling.intersect(&requested))
}

pub(super) fn capset_from_strings(items: &[String]) -> Result<CapSet, AuthError> {
    let caps = items
        .iter()
        .map(|s| Capability::parse(s).map_err(|e| AuthError::State(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CapSet(caps))
}

fn role_grants(value: &Value) -> Result<Vec<String>, AuthError> {
    let map = value
        .as_map()
        .ok_or_else(|| AuthError::State("console role must be a map".into()))?;
    optional_string_list_field(map, "grants", "console role")
}

fn role_frozen(value: &Value) -> Result<bool, AuthError> {
    let map = value
        .as_map()
        .ok_or_else(|| AuthError::State("console role must be a map".into()))?;
    optional_bool_field(map, "frozen", "console role")
}
