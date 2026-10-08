//! Configuration, account, role and session management actions.

use super::*;

pub(super) async fn dispatch(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let out = match call.action.as_str() {
        ACTION_CONFIG_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let path = string_arg(&mut input, "path")?;
            let path = Path::parse(&path)?;
            let value = mgmt::inspect_config(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_CONFIG_LIST => {
            let mut input = input_map(input_value(&call.input)?)?;
            let prefix = string_arg(&mut input, "prefix")?;
            let prefix = Path::parse(&prefix)?;
            let entries = mgmt::inspect_config_prefix(
                context.state,
                principal,
                prefix,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_CONFIG_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let path = string_arg(&mut input, "path")?;
            let value = value_arg(&mut input, "value")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            let path = Path::parse(&path)?;
            require_config_write_safety(principal, &path)?;
            mgmt::write_config(context.state, principal, path, value, expected_version).await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_ACCESS_USER_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            let path = auth::user_path(&username)?;
            let value = mgmt::inspect(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_ACCESS_USER_LIST => {
            let entries = mgmt::inspect_prefix(
                context.state,
                principal,
                Path::parse(auth::USERS_PREFIX)?,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_ACCESS_USER_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            let value = value_arg(&mut input, "value")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = auth::user_path(&username)?;
            mgmt::write_dedicated_config(context.state, principal, path, value, expected_version)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_ACCESS_USER_DISABLE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = auth::user_path(&username)?;
            let Some(mut value) = mgmt::inspect(context.state, principal, &path).await? else {
                return Err(ConsoleError::BadRequest("unknown console user".into()));
            };
            match value.as_map().cloned() {
                Some(mut m) => {
                    m.insert("status".into(), Value::string("disabled".into()))
                        .map_err(|error| ConsoleError::BadRequest(error.to_string()))?;
                    value = Value::from(m);
                }
                _ => {
                    return Err(ConsoleError::BadRequest(
                        "console user must be an object".into(),
                    ));
                }
            }
            mgmt::write_dedicated_config(context.state, principal, path, value, expected_version)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_ACCESS_ROLE_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let role = string_arg(&mut input, "role")?;
            let path = auth::role_path(&role)?;
            let value = mgmt::inspect(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_ACCESS_ROLE_LIST => {
            let entries = mgmt::inspect_prefix(
                context.state,
                principal,
                Path::parse(auth::ROLES_PREFIX)?,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_ACCESS_ROLE_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let role = string_arg(&mut input, "role")?;
            let value = value_arg(&mut input, "value")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = auth::role_path(&role)?;
            mgmt::write_dedicated_config(context.state, principal, path, value, expected_version)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_ACCESS_SESSION_LIST => {
            session_list(context, principal, list_request(&call.input)?).await?
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
