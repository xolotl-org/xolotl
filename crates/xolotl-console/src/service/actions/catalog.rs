//! Protocol, resource and authority discovery actions.

use super::*;

pub(super) async fn dispatch(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let out = match call.action.as_str() {
        ACTION_PROTOCOL_DESCRIBE => serde_value(crate::service::protocol_greeting(context.state)?)?,
        ACTION_PROTOCOL_REGISTRY_SNAPSHOT => {
            protocol::registry_snapshot_to_value(registry_snapshot(context.state)?)
        }
        ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET => {
            let mut input = input_map(input_value(&call.input)?)?;
            let action_id = string_arg(&mut input, "action")?;
            context
                .state
                .registry
                .action_by_id(&action_id)
                .map(protocol::action_descriptor_to_value)
                .ok_or_else(|| {
                    ConsoleError::BadRequest(format!("unknown action descriptor: {action_id}"))
                })?
        }
        ACTION_RESOURCE_TYPE_LIST => context.state.registry.resource_type_list_value(),
        ACTION_RESOURCE_TYPE_DESCRIBE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let resource_type = string_arg(&mut input, "resource_type")?;
            context
                .state
                .registry
                .resource_type_descriptor_value(&resource_type)
                .ok_or_else(|| {
                    ConsoleError::BadRequest(format!("unknown resource type: {resource_type}"))
                })?
        }
        ACTION_RESOURCE_VIEW_DESCRIBE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let view = string_arg(&mut input, "view")?;
            context
                .state
                .registry
                .resource_view_descriptor_value(&view)
                .ok_or_else(|| ConsoleError::BadRequest(format!("unknown resource view: {view}")))?
        }
        ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE => authority_principal_effective(principal)?,
        ACTION_AUTHORITY_ACTION_MATRIX => {
            let mut input = input_map(input_value(&call.input)?)?;
            let domain = optional_string_arg(&mut input, "domain")?;
            authority_action_matrix(context.state, principal, domain.as_deref())?
        }
        ACTION_AUTHORITY_RESOURCE_ACCESS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let target = string_arg(&mut input, "target")?;
            let verb = string_arg(&mut input, "verb")?;
            authority_resource_access(context, principal, &target, &verb).await?
        }
        ACTION_AUTHORITY_ACTION_EXPLAIN => {
            let mut input = input_map(input_value(&call.input)?)?;
            let action_id = string_arg(&mut input, "action")?;
            authority_action_explain(context.state, principal, &action_id)?
        }
        other => {
            return Err(ConsoleError::BadRequest(format!(
                "unknown console action: {other}"
            )));
        }
    };
    Ok(ActionResult::value(
        out,
        server_rev_hint(context.state),
        registry_rev(context.state),
    ))
}

fn authority_principal_effective(principal: &ConsolePrincipal) -> Result<Value, ConsoleError> {
    let grants = principal
        .grants
        .iter()
        .map(|cap| Value::string(cap.to_string()))
        .collect::<Vec<_>>();
    let root_data_authority = serde_value(protocol::root_data_authority())?;
    Ok(map_value([
        ("username", Value::string(principal.username.clone())),
        ("authentication", principal.authentication.to_value()),
        (
            "identity_path",
            Value::string(principal.identity_path.clone()),
        ),
        (
            "mfa_level",
            Value::integer(i64::from(principal.authentication.mfa_level())),
        ),
        ("grant_count", Value::integer(grants.len() as i64)),
        ("grants", Value::list(grants)),
        ("root_data_authority", root_data_authority),
    ]))
}

fn authority_action_matrix(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    domain: Option<&str>,
) -> Result<Value, ConsoleError> {
    let rows = protocol::action_descriptors()
        .iter()
        .filter(|descriptor| state.registry.action_enabled(&descriptor.id))
        .filter(|descriptor| domain.is_none_or(|d| descriptor.domain == d))
        .map(|descriptor| authority_action_row(principal, descriptor))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::list(rows))
}

fn authority_action_explain(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    action_id: &str,
) -> Result<Value, ConsoleError> {
    let descriptor = protocol::action_descriptors()
        .iter()
        .find(|descriptor| descriptor.id == action_id)
        .filter(|descriptor| state.registry.action_enabled(&descriptor.id))
        .ok_or_else(|| {
            ConsoleError::BadRequest(format!("unknown action descriptor: {action_id}"))
        })?;
    authority_action_row(principal, descriptor)
}

fn authority_action_row(
    principal: &ConsolePrincipal,
    descriptor: &ActionDescriptor,
) -> Result<Value, ConsoleError> {
    let checks = descriptor
        .authority_templates
        .iter()
        .map(|required| authority_required_check(principal, required))
        .collect::<Vec<_>>();
    let templates_covered = checks.iter().all(|check| {
        check
            .as_map()
            .and_then(|map| map.get("coverage"))
            .and_then(Value::as_str)
            == Some("unconditional")
    });
    let visibility_gate = action_needs_visibility_gate(descriptor);
    let status = if descriptor.requires_step_up && principal.authentication.mfa_level() < 2 {
        "step_up_required"
    } else if visibility_gate {
        "visibility_gate_required"
    } else if !templates_covered || descriptor.id == protocol::ACTION_RUNTIME_RESOURCE_DESCRIBE {
        "input_required"
    } else {
        "preconditions_met"
    };
    let why = authority_why(status, descriptor);
    let risk = serde_value(&descriptor.risk)?;
    let visibility = serde_value(&descriptor.visibility)?;
    Ok(map_value([
        ("action", Value::string(descriptor.id.clone())),
        ("domain", Value::string(descriptor.domain.clone())),
        ("status", Value::string(status.into())),
        ("risk", risk),
        ("visibility", visibility),
        ("templates_covered", Value::boolean(templates_covered)),
        ("advisory", Value::boolean(true)),
        (
            "requires_step_up",
            Value::boolean(descriptor.requires_step_up),
        ),
        (
            "mfa_level",
            Value::integer(i64::from(principal.authentication.mfa_level())),
        ),
        ("requires_visibility_gate", Value::boolean(visibility_gate)),
        ("authority", Value::list(checks)),
        (
            "why",
            Value::list(why.into_iter().map(Value::string).collect()),
        ),
    ]))
}

fn authority_required_check(principal: &ConsolePrincipal, required: &AuthorityTemplate) -> Value {
    let mut row = BTreeMap::new();
    row.insert("verb".into(), Value::string(required.verb.clone()));
    row.insert("target".into(), Value::string(required.target.clone()));
    match required_capability(required) {
        Ok(required_cap) => {
            let allowed = principal
                .grants
                .iter()
                .any(|grant| grant.predicate.is_none() && grant.covers_cap(&required_cap));
            let conditional = !allowed
                && principal.grants.iter().any(|grant| {
                    grant.predicate.is_some() && grant.covers_cap_pattern(&required_cap)
                });
            row.insert(
                "coverage".into(),
                Value::string(
                    if allowed {
                        "unconditional"
                    } else if conditional {
                        "predicate_bound"
                    } else {
                        "uncovered"
                    }
                    .into(),
                ),
            );
        }
        Err(e) => {
            row.insert("coverage".into(), Value::string("invalid_template".into()));
            row.insert(
                "why_not".into(),
                Value::string(format!("descriptor authority is malformed: {e:?}")),
            );
        }
    }
    Value::map(row)
}

async fn authority_resource_access(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    target: &str,
    verb: &str,
) -> Result<Value, ConsoleError> {
    validate_authority_verb(verb)?;
    let path = Path::parse(target)?;
    if path
        .segments()
        .iter()
        .any(|seg| matches!(seg.as_str(), "*" | "**"))
    {
        return Err(ConsoleError::BadRequest(
            "authority.resource.access requires a concrete target path".into(),
        ));
    }
    let is_local_state = path.scheme() == "state" && path.cluster().is_none();
    if is_local_state && xolotl_types::is_vault_reserved(&path) {
        return Ok(map_value([
            ("target", Value::string(path.to_string())),
            ("verb", Value::string(verb.to_string())),
            ("allowed", Value::boolean(false)),
            ("why_not", Value::string("secret_custody_required".into())),
        ]));
    }

    let result = if matches!(verb, "read" | "write" | "append" | "subscribe") && is_local_state {
        auth::authorize_path(&context.state.state, principal, verb, &path, None)
            .await
            .map(|_| "auth.authorize_path")
    } else {
        let allowed = principal.grants.contains(verb, &path);
        if allowed {
            Ok("capset.contains")
        } else {
            Err(auth::AuthError::PermissionDenied)
        }
    };
    let mut row = BTreeMap::new();
    row.insert("target".into(), Value::string(path.to_string()));
    row.insert("verb".into(), Value::string(verb.to_string()));
    match result {
        Ok(via) => {
            row.insert("allowed".into(), Value::boolean(true));
            row.insert("via".into(), Value::string(via.into()));
        }
        Err(e) => {
            row.insert("allowed".into(), Value::boolean(false));
            row.insert("why_not".into(), Value::string(e.to_string()));
        }
    }
    Ok(Value::map(row))
}

#[cfg(test)]
mod authority_coverage_tests {
    use super::*;
    use crate::{AuthenticationEvidence, PrimaryAuthentication};

    #[test]
    fn predicate_bound_grant_is_discovered_without_claiming_unconditional_authority()
    -> anyhow::Result<()> {
        let required = AuthorityTemplate {
            verb: "read".into(),
            target: "state://memory/item".into(),
        };
        for (grants, expected) in [
            (vec!["read://state/memory/**"], "unconditional"),
            (
                vec!["read://state/memory/**@account=alice"],
                "predicate_bound",
            ),
            (vec!["read://state/other/**"], "uncovered"),
        ] {
            let principal = ConsolePrincipal {
                authority_id: "local".into(),
                username: "reader".into(),
                account_id: "reader-account".into(),
                identity_path: "identity://console/accounts/reader-account".into(),
                grants: xolotl_types::CapSet::from_strs(grants)?,
                authority_ceiling: None,
                authentication: AuthenticationEvidence {
                    primary: PrimaryAuthentication::Password { verified_at: 0 },
                    secondary: None,
                },
            };
            let row = authority_required_check(&principal, &required);
            anyhow::ensure!(
                row.as_map()
                    .and_then(|row| row.get("coverage"))
                    .and_then(Value::as_str)
                    == Some(expected),
                "unexpected authority coverage for {expected}",
            );
        }
        Ok(())
    }
}
