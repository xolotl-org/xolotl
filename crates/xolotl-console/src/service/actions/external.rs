//! External installation, manifest, projection and pairing actions.

use super::*;

pub(super) async fn dispatch(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let out = match call.action.as_str() {
        ACTION_EXTERNAL_INSTALLATION_LIST => {
            crate::service::installations::list(
                context.state,
                principal,
                list_request(&call.input)?,
            )
            .await?
        }
        ACTION_EXTERNAL_INSTALLATION_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            crate::service::installations::read(context.state, principal, &id)
                .await?
                .map(serde_value)
                .transpose()?
                .unwrap_or(Value::null())
        }
        ACTION_EXTERNAL_INSTALLATION_INSTALL | ACTION_EXTERNAL_INSTALLATION_UPDATE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            let expected_epoch = optional_u64_arg(&mut input, "expected_installation_epoch")?;
            let expected = match (expected_epoch, expected_version) {
                (None, None) => None,
                (Some(installation_epoch), Some(version)) if installation_epoch != 0 => {
                    Some(xolotl_source::ExternalInstallationRevision {
                        installation_epoch,
                        version,
                    })
                }
                _ => {
                    return Err(ConsoleError::BadRequest(
                        "expected_installation_epoch and expected_version must be supplied together"
                            .into(),
                    ));
                }
            };
            require_step_up(principal)?;
            let definition = validate_external_installation_def(
                &id,
                &def,
                context
                    .state
                    .source_management
                    .as_deref()
                    .map(|owner| owner as &dyn xolotl_source::SourceDeclarationAdmission),
            )?;
            if call.action == ACTION_EXTERNAL_INSTALLATION_INSTALL && expected.is_some() {
                return Err(ConsoleError::BadRequest(
                    "installation install requires no expected revision".into(),
                ));
            }
            if call.action == ACTION_EXTERNAL_INSTALLATION_UPDATE && expected.is_none() {
                return Err(ConsoleError::BadRequest(
                    "installation update requires the current installation epoch and version"
                        .into(),
                ));
            }
            crate::service::installations::write(context.state, principal, definition, expected)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_EXTERNAL_INSTALLATION_UNINSTALL => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?
                .ok_or_else(|| ConsoleError::BadRequest("expected_version is required".into()))?;
            let installation_epoch = optional_u64_arg(&mut input, "expected_installation_epoch")?
                .filter(|epoch| *epoch != 0)
                .ok_or_else(|| {
                    ConsoleError::BadRequest("expected_installation_epoch is required".into())
                })?;
            require_step_up(principal)?;
            crate::service::installations::uninstall(
                context.state,
                principal,
                &id,
                xolotl_source::ExternalInstallationRevision {
                    installation_epoch,
                    version: expected_version,
                },
            )
            .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_EXTERNAL_INSTALLATION_START => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            require_step_up(principal)?;
            let spec = proc_spec_from_installation(context, principal, &id).await?;
            let value = serde_json::from_value(serde_json::to_value(spec).map_err(|e| {
                ConsoleError::BadRequest(format!("proc spec serialization failed: {e}"))
            })?)
            .map_err(|e| ConsoleError::BadRequest(format!("proc spec conversion failed: {e}")))?;
            invoke_effect(
                context,
                principal,
                crate::paths::PROCESS_SPAWN_EFFECT,
                value,
            )
            .await?
        }
        ACTION_EXTERNAL_INSTALLATION_STOP => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            require_step_up(principal)?;
            validate_path_segment(&id, "external installation id")?;
            invoke_effect(
                context,
                principal,
                crate::paths::PROCESS_KILL_EFFECT,
                map_value([("id", Value::string(id))]),
            )
            .await?
        }
        ACTION_EXTERNAL_INSTALLATION_REVOKE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let installation_id = string_arg(&mut input, "installation_id")?;
            let credential_generation_floor =
                optional_i64_arg(&mut input, "credential_generation_floor")?;
            require_step_up(principal)?;
            if matches!(credential_generation_floor, Some(floor) if floor < 1) {
                return Err(ConsoleError::BadRequest(
                    "credential_generation_floor must be at least 1".into(),
                ));
            }
            let installation =
                read_external_installation(context, principal, &installation_id).await?;
            let mut m = BTreeMap::new();
            m.insert("installation_id".into(), Value::string(installation.id));
            if let Some(floor) = credential_generation_floor {
                m.insert("credential_generation_floor".into(), Value::integer(floor));
            }
            invoke_effect(
                context,
                principal,
                crate::paths::EXTERNAL_REVOKE_EFFECT,
                Value::map(m),
            )
            .await?
        }
        ACTION_EXTERNAL_MANIFEST_LIST => {
            let entries = mgmt::inspect_prefix(
                context.state,
                principal,
                Path::parse(crate::paths::MANIFESTS_PREFIX)?,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_EXTERNAL_MANIFEST_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let platform = string_arg(&mut input, "platform")?;
            let path = external_manifest_path(&platform)?;
            let value = mgmt::inspect(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_EXTERNAL_MANIFEST_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let platform = string_arg(&mut input, "platform")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = external_manifest_path(&platform)?;
            mgmt::write_dedicated_config(context.state, principal, path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(
                server_rev_hint(context.state),
                registry_rev(context.state),
            ));
        }
        ACTION_PROJECTION_IN_PROCESS_STATUS_LIST => {
            let entries = mgmt::inspect_prefix(
                context.state,
                principal,
                Path::parse(crate::paths::PROJECTION_STATUS_PREFIX)?,
                list_request(&call.input)?,
            )
            .await?;
            entries_value(entries)
        }
        ACTION_PROJECTION_IN_PROCESS_STATUS_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let path = projection_status_path(&id)?;
            let value = mgmt::inspect(context.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_PAIRING_CREATE => {
            let mut input_map = input_map(input_value(&call.input)?)?;
            let pairing_id = string_arg(&mut input_map, "pairing_id")?;
            let installation_id = string_arg(&mut input_map, "installation_id")?;
            validate_path_segment(&pairing_id, "pairing id")?;
            validate_path_segment(&installation_id, "installation id")?;
            let allowed_roles = if input_map.get("allowed_roles").is_some() {
                Some(string_list_arg(&mut input_map, "allowed_roles")?)
            } else {
                None
            };
            let expires_at = optional_i64_arg(&mut input_map, "expires_at")?;
            if expires_at.is_some_and(|expires_at| expires_at < 0) {
                return Err(ConsoleError::BadRequest(
                    "expires_at must be a non-negative integer".into(),
                ));
            }
            let reveal_display_secret =
                optional_bool_arg(&mut input_map, "reveal_display_secret")?.unwrap_or(false);
            if let Some(field) = input_map.keys().next() {
                return Err(ConsoleError::BadRequest(format!(
                    "pairing.create does not accept field {field:?}"
                )));
            }
            let mut effect_input = vec![
                ("pairing_id", Value::string(pairing_id)),
                ("installation_id", Value::string(installation_id)),
            ];
            if let Some(allowed_roles) = allowed_roles {
                effect_input.push((
                    "allowed_roles",
                    Value::list(allowed_roles.into_iter().map(Value::string).collect()),
                ));
            }
            if let Some(expires_at) = expires_at {
                effect_input.push(("expires_at", Value::integer(expires_at)));
            }
            require_step_up(principal)?;
            pairing_action(
                context,
                principal,
                crate::paths::PAIRING_CREATE_EFFECT,
                map_value(effect_input),
                reveal_display_secret,
            )
            .await?
        }
        ACTION_PAIRING_APPROVE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let pairing_id = string_arg(&mut input, "pairing_id")?;
            let approved_roles = string_list_arg(&mut input, "approved_roles")?;
            require_step_up(principal)?;
            validate_path_segment(&pairing_id, "pairing id")?;
            invoke_effect(
                context,
                principal,
                crate::paths::PAIRING_APPROVE_EFFECT,
                map_value([
                    ("pairing_id", Value::string(pairing_id)),
                    (
                        "approved_roles",
                        Value::list(approved_roles.into_iter().map(Value::string).collect()),
                    ),
                ]),
            )
            .await?
        }
        ACTION_PAIRING_DENY => {
            let mut input = input_map(input_value(&call.input)?)?;
            let pairing_id = string_arg(&mut input, "pairing_id")?;
            require_step_up(principal)?;
            validate_path_segment(&pairing_id, "pairing id")?;
            invoke_effect(
                context,
                principal,
                crate::paths::PAIRING_DENY_EFFECT,
                map_value([("pairing_id", Value::string(pairing_id))]),
            )
            .await?
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

async fn pairing_action(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    effect: &str,
    input: Value,
    reveal_display_secret: bool,
) -> Result<Value, ConsoleError> {
    reject_secret_fields(&input)?;
    let mut out = invoke_effect(context, principal, effect, input).await?;
    if reveal_display_secret {
        let pairing_id = out
            .as_map()
            .and_then(|m| m.get("pairing_id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ConsoleError::Operation("pairing result has no pairing_id".into()))?;
        if let Some(secret) = context
            .state
            .pairing_display
            .take_display_secret(&pairing_id)
        {
            match out.as_map().cloned() {
                Some(mut m) => {
                    m.insert("display_secret".into(), Value::string(secret))
                        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
                    out = Value::from(m);
                }
                _ => {
                    return Err(ConsoleError::Operation(
                        "pairing result is not an object".into(),
                    ));
                }
            }
        }
    }
    Ok(out)
}

async fn proc_spec_from_installation(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    id: &str,
) -> Result<ProcSpec, ConsoleError> {
    let def = read_external_installation(context, principal, id).await?;
    validate_source_installation(
        &def,
        context
            .state
            .source_management
            .as_deref()
            .map(|owner| owner as &dyn xolotl_source::SourceDeclarationAdmission),
    )?;
    Ok(proc_spec_from_transport(def.id, def.transport))
}

async fn read_external_installation(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    id: &str,
) -> Result<ExternalInstallationDef, ConsoleError> {
    let record = crate::service::installations::read(context.state, principal, id)
        .await?
        .ok_or_else(|| ConsoleError::BadRequest("external installation is not installed".into()))?;
    Ok(record.definition)
}

fn proc_spec_from_transport(id: String, transport: Transport) -> ProcSpec {
    let command = match &transport {
        Transport::Stdio { command, args } => command.as_ref().map(|cmd| {
            std::iter::once(cmd.clone())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>()
        }),
        _ => None,
    };
    ProcSpec {
        id,
        transport,
        command,
        env: BTreeMap::new(),
        cwd: None,
        restart: RestartPolicy::default(),
    }
}

async fn invoke_effect(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    effect: &str,
    input: Value,
) -> Result<Value, ConsoleError> {
    let path = Path::parse(effect)?;
    auth::authorize_path(
        &context.state.state,
        principal,
        "perform",
        &path,
        Some(&input),
    )
    .await?;
    let compiled = recipes::CompiledRecipe::effect(path, input)
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    recipes::execute(context.state, principal, compiled).await
}
