//! Local federation catalog actions. The injected port owns atomic CAS;
//! Console owns session admission, capability checks, audit and work bounds.

use std::collections::BTreeMap;

use data_encoding::HEXLOWER;
use xolotl_federation::{
    AuthorityOwner, ExportAccess, ExportAuthorityEntry, ExportName, FederationError,
    FederationManagement, FederationNodeId, MAX_MANAGEMENT_PAGE, PeerAdmission, PeerAdmissionEntry,
    PeerAuthorityEntry,
};
use xolotl_kernel::host::{BlockingSpawnError, blocking};
use xolotl_types::{Path, Value, ValueMap, ValueView};

use super::{ActionContext, ConsoleError, ConsolePrincipal, input_map, input_value, map_value};
use crate::{auth, protocol};

pub(super) async fn dispatch(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &protocol::ActionCall,
) -> Result<Value, ConsoleError> {
    let mut input = input_map(input_value(&call.input)?)?;
    match call.action.as_str() {
        protocol::ACTION_FEDERATION_PEER_LIST => list_peers(context, principal, &mut input).await,
        protocol::ACTION_FEDERATION_PEER_READ => {
            let peer = take_peer(&mut input)?;
            reject_extra(&input)?;
            let path = peer_path(peer)?;
            auth::authorize_path(&context.state.state, principal, "read", &path, None).await?;
            let row = run(context, move |owner| owner.peer(peer)).await?;
            Ok(row.map_or(Value::null(), peer_value))
        }
        protocol::ACTION_FEDERATION_PEER_WRITE_CAS => {
            let peer = take_peer(&mut input)?;
            let enabled = take_bool(&mut input, "enabled")?;
            let expected = take_revision(&mut input)?;
            reject_extra(&input)?;
            let path = peer_path(peer)?;
            let proposed = map_value([
                ("peer_node", Value::string(node_text(peer))),
                ("enabled", Value::boolean(enabled)),
            ]);
            authorize_write(context, principal, &path, &proposed).await?;
            let revision = run(context, move |owner| {
                owner.set_peer(peer, expected, enabled)
            })
            .await?;
            Ok(revision_value(revision))
        }
        protocol::ACTION_FEDERATION_PEER_ADMISSION_READ => {
            let peer = take_peer(&mut input)?;
            reject_extra(&input)?;
            let path = online_admission_path(peer)?;
            auth::authorize_path(&context.state.state, principal, "read", &path, None).await?;
            let row = run(context, move |owner| owner.online_admission(peer)).await?;
            Ok(row.map_or(Value::null(), admission_value))
        }
        protocol::ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS => {
            let peer = take_peer(&mut input)?;
            let admission = take_admission(&mut input)?;
            let expected = take_revision(&mut input)?;
            reject_extra(&input)?;
            let path = online_admission_path(peer)?;
            let proposed = Value::map(admission_fields(peer, &admission));
            authorize_write(context, principal, &path, &proposed).await?;
            let revision = run(context, move |owner| {
                owner.set_online_admission(peer, expected, admission)
            })
            .await?;
            Ok(revision_value(revision))
        }
        protocol::ACTION_FEDERATION_EXPORT_READ => {
            let peer = take_peer(&mut input)?;
            let export = take_export(&mut input)?;
            reject_extra(&input)?;
            let path = export_path(peer)?;
            auth::authorize_path(&context.state.state, principal, "read", &path, None).await?;
            let row = run(context, move |owner| owner.export(peer, &export)).await?;
            Ok(row.map_or(Value::null(), export_value))
        }
        protocol::ACTION_FEDERATION_EXPORT_LIST => {
            list_exports(context, principal, &mut input).await
        }
        protocol::ACTION_FEDERATION_EXPORT_WRITE_CAS => {
            let peer = take_peer(&mut input)?;
            let export = take_export(&mut input)?;
            let access = ExportAccess {
                serve: take_bool(&mut input, "serve")?,
                receive: take_bool(&mut input, "receive")?,
            };
            let expected = take_revision(&mut input)?;
            reject_extra(&input)?;
            let path = export_path(peer)?;
            let proposed = map_value([
                ("peer_node", Value::string(node_text(peer))),
                ("export", Value::string(export.as_str().to_owned())),
                ("serve", Value::boolean(access.serve)),
                ("receive", Value::boolean(access.receive)),
            ]);
            authorize_write(context, principal, &path, &proposed).await?;
            let revision = run(context, move |owner| {
                owner.set_export(peer, export, expected, access)
            })
            .await?;
            Ok(revision_value(revision))
        }
        _ => Err(ConsoleError::BadRequest("unknown federation action".into())),
    }
}

async fn list_exports(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    input: &mut ValueMap,
) -> Result<Value, ConsoleError> {
    let peer = take_peer(input)?;
    let limit = take_limit(input)?;
    let after = input
        .remove("cursor")
        .map(|value| match value.view() {
            ValueView::Str(raw) => ExportName::new(raw)
                .map_err(|_error| ConsoleError::BadRequest("invalid export cursor".into())),
            _ => Err(ConsoleError::BadRequest(
                "cursor must be an export name".into(),
            )),
        })
        .transpose()?;
    reject_extra(input)?;
    auth::authorize_prefix_read(&context.state.state, principal, &export_path(peer)?).await?;
    let mut rows = run(context, move |owner| {
        owner.scan_exports(peer, after.as_ref(), limit + 1)
    })
    .await?;
    if rows.len() > limit + 1 {
        return Err(ConsoleError::Operation(
            "federation catalog exceeded its requested page bound".into(),
        ));
    }
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if more {
        rows.last()
            .map(|row| Value::string(row.export.as_str().to_owned()))
            .unwrap_or(Value::null())
    } else {
        Value::null()
    };
    Ok(map_value([
        (
            "entries",
            Value::list(rows.into_iter().map(export_value).collect()),
        ),
        ("next_cursor", next_cursor),
    ]))
}

async fn list_peers(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    input: &mut ValueMap,
) -> Result<Value, ConsoleError> {
    let limit = take_limit(input)?;
    let after = input
        .remove("cursor")
        .map(|value| match value.view() {
            ValueView::Str(raw) => parse_node(raw),
            _ => Err(ConsoleError::BadRequest("cursor must be a node ID".into())),
        })
        .transpose()?;
    reject_extra(input)?;
    auth::authorize_prefix_read(
        &context.state.state,
        principal,
        &Path::parse(crate::paths::FEDERATION_PEERS_PREFIX)?,
    )
    .await?;
    // One lookahead row determines whether another page exists. Every returned
    // row is small and the backend is forbidden to exceed this fixed page size.
    let mut rows = run(context, move |owner| owner.scan_peers(after, limit + 1)).await?;
    if rows.len() > limit + 1 {
        return Err(ConsoleError::Operation(
            "federation catalog exceeded its requested page bound".into(),
        ));
    }
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if more {
        rows.last()
            .map(|row| Value::string(node_text(row.peer)))
            .unwrap_or(Value::null())
    } else {
        Value::null()
    };
    Ok(map_value([
        (
            "entries",
            Value::list(rows.into_iter().map(peer_value).collect()),
        ),
        ("next_cursor", next_cursor),
    ]))
}

fn take_limit(input: &mut ValueMap) -> Result<usize, ConsoleError> {
    const DEFAULT: usize = 64;
    let Some(value) = input.remove("limit") else {
        return Ok(DEFAULT);
    };
    let ValueView::Int(raw) = value.view() else {
        return Err(ConsoleError::BadRequest(
            "limit must be a positive integer".into(),
        ));
    };
    let limit = usize::try_from(raw)
        .ok()
        .filter(|limit| (1..MAX_MANAGEMENT_PAGE).contains(limit))
        .ok_or_else(|| ConsoleError::BadRequest("limit must be between 1 and 255".into()))?;
    Ok(limit)
}

fn take_peer(input: &mut ValueMap) -> Result<FederationNodeId, ConsoleError> {
    let Some(value) = input.remove("peer_node") else {
        return Err(ConsoleError::BadRequest("peer_node is required".into()));
    };
    let ValueView::Str(raw) = value.view() else {
        return Err(ConsoleError::BadRequest(
            "peer_node must be a node ID".into(),
        ));
    };
    parse_node(raw)
}

fn parse_node(raw: &str) -> Result<FederationNodeId, ConsoleError> {
    let mut bytes = [0; FederationNodeId::LEN];
    if raw.len() != bytes.len() * 2 || HEXLOWER.decode_mut(raw.as_bytes(), &mut bytes).is_err() {
        return Err(ConsoleError::BadRequest(
            "node ID must be 96 lowercase hexadecimal digits".into(),
        ));
    }
    Ok(FederationNodeId::from_bytes(bytes))
}

fn take_export(input: &mut ValueMap) -> Result<ExportName, ConsoleError> {
    let Some(value) = input.remove("export") else {
        return Err(ConsoleError::BadRequest("export is required".into()));
    };
    let ValueView::Str(raw) = value.view() else {
        return Err(ConsoleError::BadRequest("export must be a string".into()));
    };
    ExportName::new(raw).map_err(|_error| ConsoleError::BadRequest("invalid export name".into()))
}

fn take_bool(input: &mut ValueMap, name: &str) -> Result<bool, ConsoleError> {
    let value = input
        .remove(name)
        .ok_or_else(|| ConsoleError::BadRequest(format!("{name} is required")))?;
    value
        .as_bool()
        .ok_or_else(|| ConsoleError::BadRequest(format!("{name} must be a bool")))
}

fn take_admission(input: &mut ValueMap) -> Result<PeerAdmission, ConsoleError> {
    let generation = input
        .remove("minimum_online_generation")
        .ok_or_else(|| ConsoleError::BadRequest("minimum_online_generation is required".into()))?;
    let generation = match generation.view() {
        ValueView::Int(value) if value > 0 => value as u64,
        ValueView::Str(raw) if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) => raw
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| ConsoleError::BadRequest("invalid minimum_online_generation".into()))?,
        _ => {
            return Err(ConsoleError::BadRequest(
                "invalid minimum_online_generation".into(),
            ));
        }
    };
    let digest_values = input
        .remove("allowed_authorization_digests")
        .ok_or_else(|| {
            ConsoleError::BadRequest("allowed_authorization_digests is required".into())
        })?;
    let values = digest_values.as_list().ok_or_else(|| {
        ConsoleError::BadRequest("allowed_authorization_digests must be a list".into())
    })?;
    if values.len() > PeerAdmission::MAX_AUTHORIZATIONS {
        return Err(ConsoleError::BadRequest(
            "too many online authorization digests".into(),
        ));
    }
    let mut digests = Vec::with_capacity(values.len());
    for value in values {
        let raw = value.as_str().ok_or_else(|| {
            ConsoleError::BadRequest("online authorization digest must be a string".into())
        })?;
        let mut bytes = [0; 48];
        if raw.len() != bytes.len() * 2 || HEXLOWER.decode_mut(raw.as_bytes(), &mut bytes).is_err()
        {
            return Err(ConsoleError::BadRequest(
                "online authorization digest must be 96 lowercase hexadecimal digits".into(),
            ));
        }
        digests.push(bytes);
    }
    let admission = PeerAdmission {
        minimum_online_generation: generation,
        allowed_authorization_digests: digests,
    };
    admission
        .validate()
        .map_err(|_error| ConsoleError::BadRequest("invalid online admission".into()))?;
    Ok(admission)
}

fn take_revision(input: &mut ValueMap) -> Result<Option<u64>, ConsoleError> {
    let Some(value) = input.remove("expected_revision") else {
        return Ok(None);
    };
    match value.view() {
        ValueView::Null => Ok(None),
        ValueView::Int(raw) if raw > 0 => Ok(Some(raw as u64)),
        ValueView::Str(raw) if !raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()) => {
            raw.parse::<u64>()
                .ok()
                .filter(|revision| *revision > 0)
                .map(Some)
                .ok_or_else(|| ConsoleError::BadRequest("invalid expected_revision".into()))
        }
        _ => Err(ConsoleError::BadRequest("invalid expected_revision".into())),
    }
}

fn reject_extra(input: &ValueMap) -> Result<(), ConsoleError> {
    if input.is_empty() {
        Ok(())
    } else {
        Err(ConsoleError::BadRequest(
            "unknown federation management input field".into(),
        ))
    }
}

fn peer_path(peer: FederationNodeId) -> Result<Path, ConsoleError> {
    crate::paths::federation_peer_path(&node_text(peer)).map_err(Into::into)
}

fn export_path(peer: FederationNodeId) -> Result<Path, ConsoleError> {
    crate::paths::federation_export_path(&node_text(peer)).map_err(Into::into)
}

fn online_admission_path(peer: FederationNodeId) -> Result<Path, ConsoleError> {
    crate::paths::federation_online_admission_path(&node_text(peer)).map_err(Into::into)
}

async fn authorize_write(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    path: &Path,
    value: &Value,
) -> Result<(), ConsoleError> {
    auth::authorize_path(&context.state.state, principal, "write", path, None).await?;
    auth::authorize_path(&context.state.state, principal, "write", path, Some(value)).await?;
    Ok(())
}

async fn run<T: Send + 'static>(
    context: &ActionContext<'_>,
    work: impl FnOnce(&dyn FederationManagement) -> Result<T, FederationError> + Send + 'static,
) -> Result<T, ConsoleError> {
    let owner = context
        .state
        .federation_management
        .as_ref()
        .ok_or_else(|| ConsoleError::BadRequest("federation management is not installed".into()))?
        .clone();
    let task = blocking::dispatch(context.state.blocking_spawner(), move || {
        work(owner.as_ref())
    })
    .map_err(|error| match error {
        BlockingSpawnError::AtCapacity => ConsoleError::RateLimited,
        BlockingSpawnError::Unavailable => {
            ConsoleError::Operation("federation management worker unavailable".into())
        }
    })?;
    task.await
        .map_err(|_error| ConsoleError::Operation("federation management worker failed".into()))?
        .map_err(Into::into)
}

fn node_text(node: FederationNodeId) -> String {
    HEXLOWER.encode(node.as_bytes())
}

fn owner_text(owner: AuthorityOwner) -> &'static str {
    match owner {
        AuthorityOwner::Application => "application",
        AuthorityOwner::Manifest => "manifest",
    }
}

fn revision_value(revision: u64) -> Value {
    map_value([("revision", Value::string(revision.to_string()))])
}

fn peer_value(row: PeerAuthorityEntry) -> Value {
    map_value([
        ("peer_node", Value::string(node_text(row.peer))),
        ("revision", Value::string(row.revision.to_string())),
        ("enabled", Value::boolean(row.enabled)),
        ("owner", Value::string(owner_text(row.owner).into())),
    ])
}

fn admission_fields(peer: FederationNodeId, admission: &PeerAdmission) -> BTreeMap<String, Value> {
    [
        ("peer_node", Value::string(node_text(peer))),
        (
            "minimum_online_generation",
            Value::string(admission.minimum_online_generation.to_string()),
        ),
        (
            "allowed_authorization_digests",
            Value::list(
                admission
                    .allowed_authorization_digests
                    .iter()
                    .map(|digest| Value::string(HEXLOWER.encode(digest)))
                    .collect(),
            ),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

fn admission_value(row: PeerAdmissionEntry) -> Value {
    let mut fields = admission_fields(row.peer, &row.admission);
    fields.insert("revision".into(), Value::string(row.revision.to_string()));
    fields.insert("owner".into(), Value::string(owner_text(row.owner).into()));
    Value::map(fields)
}

fn export_value(row: ExportAuthorityEntry) -> Value {
    map_value([
        ("peer_node", Value::string(node_text(row.peer))),
        ("export", Value::string(row.export.as_str().to_owned())),
        ("revision", Value::string(row.revision.to_string())),
        ("serve", Value::boolean(row.access.serve)),
        ("receive", Value::boolean(row.access.receive)),
        ("owner", Value::string(owner_text(row.owner).into())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context as _, ensure};
    use std::sync::Arc;
    use xolotl_kernel::Bootstrap;
    use xolotl_standard::{StandardConfig, install_standard};
    use xolotl_storage_redb::RedbStore;

    #[tokio::test]
    async fn console_catalog_checks_step_up_capability_ownership_and_cas() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let local = FederationNodeId::from_bytes([1; 48]);
        let peer = FederationNodeId::from_bytes([2; 48]);
        let manifest_peer = FederationNodeId::from_bytes([3; 48]);
        let database = RedbStore::open(directory.path().join("federation.redb"))?;
        let catalog = Arc::new(database.federation_store(local)?);
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())?;
        let bootstrap = crate::bootstrap_root_account(
            &boot,
            &xolotl_kernel::host::TokioBlockingSpawner::default(),
            crate::RootProvisioning::default(),
        )
        .await?;
        let crate::BootstrapOutcome::CreatedRandomPassword { password, .. } = bootstrap else {
            anyhow::bail!("expected fresh root account");
        };
        let state = crate::ConsoleState::with_config(
            boot,
            crate::ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                federation_management: Some(catalog.clone()),
                ..Default::default()
            },
        )?;
        let service = crate::ConsoleService::new(state.clone());
        let session = service
            .login(
                crate::LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "embedded".into(),
            )
            .await?
            .into_session()
            .ok()
            .context("root login")?;
        let authenticated = service.authenticate_session(&session.token).await?;
        let context = ActionContext {
            delivery: None,
            state: &state,
            source_addr: None,
            session_id: &authenticated.sid,
        };
        let peer_text = node_text(peer);
        let peer_create = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_PEER_WRITE_CAS.into(),
            input: map_value([
                ("peer_node", Value::string(peer_text.clone())),
                ("enabled", Value::boolean(true)),
            ]),
            ..Default::default()
        };
        let failure =
            crate::service::execute(&context, &authenticated.principal, peer_create.clone())
                .await
                .err()
                .context("step-up required")?;
        ensure!(matches!(failure, ConsoleError::StepUpRequired));
        let mut principal = authenticated.principal;
        principal.authentication.secondary = Some(crate::SecondaryAuthentication::Factor {
            factor_id: "test-factor".into(),
            provider_id: "totp".into(),
            verified_at: 1,
        });
        let created = crate::service::execute(&context, &principal, peer_create.clone()).await?;
        ensure!(
            created
                .result
                .output
                .as_ref()
                .and_then(|value| value.as_map())
                .and_then(|map| map.get("revision"))
                .and_then(Value::as_str)
                == Some("1")
        );
        let peer_read = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_PEER_READ.into(),
            input: map_value([("peer_node", Value::string(peer_text.clone()))]),
            ..Default::default()
        };
        let read = crate::service::execute(&context, &principal, peer_read).await?;
        let row = read.result.output.context("peer row")?;
        ensure!(
            row.as_map()
                .and_then(|map| map.get("owner"))
                .and_then(Value::as_str)
                == Some("application")
        );
        catalog.set_manifest_peer_authority(manifest_peer, None, true)?;
        let page = crate::service::execute(
            &context,
            &principal,
            protocol::ActionCall {
                action: protocol::ACTION_FEDERATION_PEER_LIST.into(),
                input: map_value([("limit", Value::integer(1))]),
                ..Default::default()
            },
        )
        .await?;
        let page = page.result.output.context("peer page")?;
        let page = page.as_map().context("peer page map")?;
        ensure!(
            page.get("entries")
                .and_then(Value::as_list)
                .is_some_and(|rows| rows.len() == 1)
        );
        ensure!(page.get("next_cursor").and_then(Value::as_str) == Some(peer_text.as_str()));
        let export_create = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_EXPORT_WRITE_CAS.into(),
            input: map_value([
                ("peer_node", Value::string(peer_text.clone())),
                ("export", Value::string("family photos".into())),
                ("serve", Value::boolean(true)),
                ("receive", Value::boolean(false)),
            ]),
            ..Default::default()
        };
        crate::service::execute(&context, &principal, export_create.clone()).await?;
        let export_page = crate::service::execute(
            &context,
            &principal,
            protocol::ActionCall {
                action: protocol::ACTION_FEDERATION_EXPORT_LIST.into(),
                input: map_value([("peer_node", Value::string(peer_text.clone()))]),
                ..Default::default()
            },
        )
        .await?;
        let export_page = export_page.result.output.context("export page")?;
        ensure!(
            export_page
                .as_map()
                .and_then(|map| map.get("entries"))
                .and_then(Value::as_list)
                .is_some_and(|rows| rows.len() == 1)
        );
        let digest = HEXLOWER.encode(&[7; 48]);
        let admission_write = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS.into(),
            input: map_value([
                ("peer_node", Value::string(peer_text.clone())),
                ("minimum_online_generation", Value::string("2".into())),
                (
                    "allowed_authorization_digests",
                    Value::list(vec![Value::string(digest.clone())]),
                ),
            ]),
            ..Default::default()
        };
        crate::service::execute(&context, &principal, admission_write).await?;
        let admission_read = crate::service::execute(
            &context,
            &principal,
            protocol::ActionCall {
                action: protocol::ACTION_FEDERATION_PEER_ADMISSION_READ.into(),
                input: map_value([("peer_node", Value::string(peer_text.clone()))]),
                ..Default::default()
            },
        )
        .await?;
        let admission = admission_read.result.output.context("online admission")?;
        ensure!(
            admission
                .as_map()
                .and_then(|map| map.get("minimum_online_generation"))
                .and_then(Value::as_str)
                == Some("2")
        );
        let conflict = crate::service::execute(&context, &principal, export_create)
            .await
            .err()
            .context("create-only conflict")?;
        ensure!(
            crate::protocol::ConsoleFailure::from(conflict).code
                == crate::protocol::ConsoleErrorCode::Conflict
        );
        let manifest_write = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_PEER_WRITE_CAS.into(),
            input: map_value([
                ("peer_node", Value::string(node_text(manifest_peer))),
                ("enabled", Value::boolean(false)),
                ("expected_revision", Value::integer(1)),
            ]),
            ..Default::default()
        };
        let denied = crate::service::execute(&context, &principal, manifest_write)
            .await
            .err()
            .context("manifest ownership")?;
        ensure!(
            crate::protocol::ConsoleFailure::from(denied).code
                == crate::protocol::ConsoleErrorCode::AdmissionRejected
        );
        catalog.set_manifest_peer_admission(
            manifest_peer,
            None,
            PeerAdmission {
                minimum_online_generation: 1,
                allowed_authorization_digests: vec![[9; 48]],
            },
        )?;
        let manifest_admission_write = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS.into(),
            input: map_value([
                ("peer_node", Value::string(node_text(manifest_peer))),
                ("minimum_online_generation", Value::integer(2)),
                (
                    "allowed_authorization_digests",
                    Value::list(vec![Value::string(digest)]),
                ),
                ("expected_revision", Value::integer(1)),
            ]),
            ..Default::default()
        };
        let denied = crate::service::execute(&context, &principal, manifest_admission_write)
            .await
            .err()
            .context("manifest online admission ownership")?;
        ensure!(
            crate::protocol::ConsoleFailure::from(denied).code
                == crate::protocol::ConsoleErrorCode::AdmissionRejected
        );
        let mut export_operator = principal.clone();
        export_operator.grants = xolotl_types::CapSet::from_strs([format!(
            "write://state/kernel/federation/peers/{peer_text}/exports"
        )])?;
        let export_update = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_EXPORT_WRITE_CAS.into(),
            input: map_value([
                ("peer_node", Value::string(peer_text.clone())),
                ("export", Value::string("family photos".into())),
                ("serve", Value::boolean(false)),
                ("receive", Value::boolean(true)),
                ("expected_revision", Value::integer(1)),
            ]),
            ..Default::default()
        };
        crate::service::execute(&context, &export_operator, export_update).await?;
        let denied = crate::service::execute(&context, &export_operator, peer_create.clone())
            .await
            .err()
            .context("export authority must not grant peer writes")?;
        ensure!(
            crate::protocol::ConsoleFailure::from(denied).code
                == crate::protocol::ConsoleErrorCode::Forbidden
        );
        let mut admission_operator = principal.clone();
        admission_operator.grants = xolotl_types::CapSet::from_strs([format!(
            "write://state/kernel/federation/peers/{peer_text}/online-admission"
        )])?;
        let admission_update = protocol::ActionCall {
            action: protocol::ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS.into(),
            input: map_value([
                ("peer_node", Value::string(peer_text.clone())),
                ("minimum_online_generation", Value::integer(3)),
                (
                    "allowed_authorization_digests",
                    Value::list(vec![Value::string(HEXLOWER.encode(&[7; 48]))]),
                ),
                ("expected_revision", Value::integer(1)),
            ]),
            ..Default::default()
        };
        crate::service::execute(&context, &admission_operator, admission_update).await?;
        let denied = crate::service::execute(&context, &admission_operator, peer_create.clone())
            .await
            .err()
            .context("admission authority must not grant peer writes")?;
        ensure!(
            crate::protocol::ConsoleFailure::from(denied).code
                == crate::protocol::ConsoleErrorCode::Forbidden
        );
        principal.grants =
            xolotl_types::CapSet::from_strs(["read://state/kernel/federation/peers/**"])?;
        let denied = crate::service::execute(&context, &principal, peer_create)
            .await
            .err()
            .context("write capability")?;
        ensure!(
            crate::protocol::ConsoleFailure::from(denied).code
                == crate::protocol::ConsoleErrorCode::Forbidden
        );
        Ok(())
    }
}
