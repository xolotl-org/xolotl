//! Inference declarations and routing actions.

use super::*;

pub(super) async fn dispatch(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let out = match call.action.as_str() {
        ACTION_INFERENCE_BACKEND_LIST => {
            let entries = mgmt::inspect_prefix(
                context.state,
                principal,
                Path::parse(crate::paths::INFERENCE_BACKENDS_PREFIX)?,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_INFERENCE_BACKEND_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let path = inference_backend_path(&id)?;
            let value = mgmt::inspect(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_BACKEND_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = inference_backend_path(&id)?;
            mgmt::write_dedicated_config(context.state, principal, path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_INFERENCE_MODEL_LIST => {
            let entries = mgmt::inspect_prefix(
                context.state,
                principal,
                Path::parse(crate::paths::INFERENCE_MODELS_PREFIX)?,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_INFERENCE_MODEL_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let path = inference_model_path(&id)?;
            let value = mgmt::inspect(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_MODEL_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = inference_model_path(&id)?;
            mgmt::write_dedicated_config(context.state, principal, path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_INFERENCE_GROUP_LIST => {
            let entries = mgmt::inspect_prefix(
                context.state,
                principal,
                Path::parse(crate::paths::INFERENCE_GROUPS_PREFIX)?,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_INFERENCE_GROUP_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let name = string_arg(&mut input, "name")?;
            let path = inference_group_path(&name)?;
            let value = mgmt::inspect(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_GROUP_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let name = string_arg(&mut input, "name")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = inference_group_path(&name)?;
            mgmt::write_dedicated_config(context.state, principal, path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_INFERENCE_ROUTING_READ => {
            let value = mgmt::inspect(
                context.state,
                principal,
                &Path::parse(crate::paths::INFERENCE_ROUTING_PATH)?,
            )
            .await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_ROUTING_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            mgmt::write_dedicated_config(
                context.state,
                principal,
                Path::parse(crate::paths::INFERENCE_ROUTING_PATH)?,
                def,
                expected_version,
            )
            .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
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
