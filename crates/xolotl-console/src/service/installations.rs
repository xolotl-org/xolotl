//! Console projection of the storage-owned external installation catalog.
//! Ordinary State values under the former installation prefix carry no
//! admission authority; every mutation and read uses this typed port.

use super::{
    ConsoleError, entries_value, external_installation_path, external_installation_target,
    serde_value,
};
use crate::auth::{self, ConsolePrincipal};
use crate::mgmt::{ListRequest, ManagementPage, MgmtError};
use crate::state::ConsoleState;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{num::NonZeroUsize, sync::Arc};
use xolotl_source::{
    ExternalInstallationMutation, ExternalInstallationRecord, ExternalInstallationRevision,
    SourceManagement,
};
use xolotl_types::{ExternalInstallationDef, Path, Value};

fn owner(state: &ConsoleState) -> Result<&Arc<dyn SourceManagement>, ConsoleError> {
    state.source_management.as_ref().ok_or_else(|| {
        ConsoleError::BadRequest("external installation authority is not installed".into())
    })
}

fn path(id: &str) -> Result<Path, ConsoleError> {
    external_installation_target(id)
}

pub(super) async fn read(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    id: &str,
) -> Result<Option<ExternalInstallationRecord>, ConsoleError> {
    auth::authorize_path(&state.state, principal, "read", &path(id)?, None).await?;
    owner(state)?
        .load_installation(id)
        .await
        .map_err(|error| ConsoleError::Operation(error.to_string()))
}

pub(super) async fn write(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    definition: ExternalInstallationDef,
    expected: Option<ExternalInstallationRevision>,
) -> Result<(), ConsoleError> {
    let target = path(&definition.id)?;
    auth::authorize_path(&state.state, principal, "write", &target, None).await?;
    let value = serde_value(&definition)?;
    auth::authorize_path(&state.state, principal, "write", &target, Some(&value)).await?;
    let result = owner(state)?
        .compare_install(definition, expected)
        .await
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    match result {
        ExternalInstallationMutation::Applied(_) => Ok(()),
        ExternalInstallationMutation::Conflict { current } => {
            Err(MgmtError::InstallationConflict { expected, current }.into())
        }
    }
}

pub(super) async fn uninstall(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    id: &str,
    expected: ExternalInstallationRevision,
) -> Result<(), ConsoleError> {
    auth::authorize_path(&state.state, principal, "write", &path(id)?, None).await?;
    let result = owner(state)?
        .compare_retire(id, expected)
        .await
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    match result {
        ExternalInstallationMutation::Applied(_) => Ok(()),
        ExternalInstallationMutation::Conflict { current } => {
            Err(MgmtError::InstallationConflict {
                expected: Some(expected),
                current,
            }
            .into())
        }
    }
}

pub(super) async fn list(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    request: ListRequest,
) -> Result<Value, ConsoleError> {
    let prefix = Path::parse(crate::paths::EXTERNAL_INSTALLATIONS_PREFIX)?;
    auth::authorize_prefix_read(&state.state, principal, &prefix).await?;
    let limit = request
        .limit
        .unwrap_or(256)
        .min(state.queries.max_state_list_limit);
    let limit = NonZeroUsize::new(limit)
        .ok_or_else(|| MgmtError::Query("limit must be greater than zero".into()))?;
    let budget = request
        .max_bytes
        .unwrap_or(state.queries.max_page_bytes)
        .min(state.queries.max_page_bytes);
    if budget == 0 {
        return Err(MgmtError::Query("max_bytes must be greater than zero".into()).into());
    }
    let mut after = request.cursor.as_deref().map(decode_cursor).transpose()?;
    let mut entries = Vec::with_capacity(limit.get().min(8));
    let mut used = 0usize;
    let mut more = false;
    'page: loop {
        // Bound temporary owned catalog rows independently of the caller's
        // entry limit. A single large declaration must not multiply memory
        // by a 16K-entry request before the byte budget can be enforced.
        let batch_len = (limit.get() - entries.len() + 1).min(8);
        let rows = owner(state)?
            .list_installations(
                after.as_deref(),
                NonZeroUsize::new(batch_len)
                    .ok_or_else(|| MgmtError::Query("installation page limit is invalid".into()))?,
            )
            .await
            .map_err(|error| ConsoleError::Operation(error.to_string()))?;
        let exhausted = rows.len() < batch_len;
        for record in rows {
            if entries.len() == limit.get() {
                more = true;
                break 'page;
            }
            let id = record.definition.id.clone();
            let entry_path = external_installation_path(&id)?;
            auth::authorize_path(
                &state.state,
                principal,
                "read",
                &Path::parse(&entry_path)?,
                None,
            )
            .await?;
            let value = serde_value(&record)?;
            let row_bytes = id.len()
                + serde_json::to_vec(&value)
                    .map_err(|error| ConsoleError::Operation(error.to_string()))?
                    .len();
            if used.saturating_add(row_bytes) > budget {
                if entries.is_empty() {
                    return Err(MgmtError::Query(
                        "installation record exceeds page byte budget; increase max_bytes or read it individually".into(),
                    )
                    .into());
                }
                more = true;
                break 'page;
            }
            used += row_bytes;
            entries.push((entry_path, value));
            after = Some(id);
        }
        if exhausted {
            break;
        }
    }
    let next_cursor = if more {
        Some(encode_cursor(after.as_deref().ok_or_else(|| {
            ConsoleError::Operation("installation page did not advance".into())
        })?)?)
    } else {
        None
    };
    Ok(entries_value(ManagementPage {
        entries,
        next_cursor,
    }))
}

fn encode_cursor(id: &str) -> Result<String, ConsoleError> {
    let raw = serde_json::to_vec(&("external-installations", id))
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn decode_cursor(raw: &str) -> Result<String, ConsoleError> {
    if raw.len() > 1024 {
        return Err(MgmtError::Query("cursor is too large".into()).into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_error| MgmtError::Query("invalid installation cursor".into()))?;
    let (scope, id): (String, String) = serde_json::from_slice(&bytes)
        .map_err(|_error| MgmtError::Query("invalid installation cursor".into()))?;
    if scope != "external-installations" {
        return Err(MgmtError::Query("invalid installation cursor scope".into()).into());
    }
    path(&id)?;
    Ok(id)
}
