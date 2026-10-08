//! One bounded state query per management list request.

use super::MgmtError;
use crate::auth::{self, ConsolePrincipal};
use crate::state::ConsoleState;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::num::NonZeroUsize;
use xolotl_state::{StateCursor, StateError, StateScan};
use xolotl_types::{Path, Value};

#[derive(Clone, Debug, Default)]
pub(crate) struct ListRequest {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub max_bytes: Option<usize>,
}

pub(crate) struct ManagementPage {
    pub entries: Vec<(String, Value)>,
    pub next_cursor: Option<String>,
}

fn nonzero(value: usize, name: &str) -> Result<NonZeroUsize, MgmtError> {
    NonZeroUsize::new(value)
        .ok_or_else(|| MgmtError::Query(format!("{name} must be greater than zero")))
}

pub(super) async fn read(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    prefix: Path,
    request: ListRequest,
) -> Result<ManagementPage, MgmtError> {
    let query = state_scan(&state.queries, prefix, request)?;
    let page = state.state.query(&query).await.map_err(|failure| match failure.error {
        StateError::InvalidQuery(_) => MgmtError::Query("invalid management cursor for this prefix".into()),
        StateError::RowTooLarge(_) => MgmtError::Query("state record exceeds page byte budget; increase max_bytes or read the record individually".into()),
        error => MgmtError::Operation(error.to_string()),
    })?;
    if page.next.is_some() && page.next == query.cursor {
        return Err(MgmtError::Operation(
            "state page did not advance its cursor".into(),
        ));
    }
    let mut entries = Vec::with_capacity(page.entries.len());
    for (path, value) in page.entries {
        if path != query.prefix && !query.prefix.is_prefix_of(&path) {
            return Err(MgmtError::Operation(
                "state page path is outside its prefix".into(),
            ));
        }
        auth::authorize_path(&state.state, principal, "read", &path, None).await?;
        entries.push((path.to_string(), value.value));
    }
    Ok(ManagementPage {
        entries,
        next_cursor: page
            .next
            .map(|cursor| encode_cursor(&query.prefix, cursor))
            .transpose()?,
    })
}

pub(crate) fn state_scan(
    config: &crate::state::ConsoleQueryConfig,
    prefix: Path,
    request: ListRequest,
) -> Result<StateScan, MgmtError> {
    let mut query = StateScan::new(prefix);
    query.limits.entries = nonzero(
        request
            .limit
            .unwrap_or(256)
            .min(config.max_state_list_limit),
        "limit",
    )?;
    // Leave room for Value/protobuf expansion, path wrappers and page metadata.
    let maximum = config.max_page_bytes;
    query.limits.encoded_bytes = nonzero(
        request.max_bytes.unwrap_or(maximum).min(maximum),
        "max_bytes",
    )?;
    query.cursor = request
        .cursor
        .map(|cursor| {
            if cursor.len() > 16 * 1024 {
                return Err(MgmtError::Query("cursor is too large".into()));
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(cursor)
                .map_err(|_error| MgmtError::Query("invalid page cursor".into()))?;
            let (scope, cursor): (String, Vec<u8>) = serde_json::from_slice(&bytes)
                .map_err(|_error| MgmtError::Query("invalid page cursor".into()))?;
            if scope != query.prefix.to_string() {
                return Err(MgmtError::Query(
                    "cursor belongs to a different prefix".into(),
                ));
            }
            Ok(StateCursor(cursor))
        })
        .transpose()?;
    Ok(query)
}

pub(crate) fn encode_cursor(prefix: &Path, cursor: StateCursor) -> Result<String, MgmtError> {
    let bytes = serde_json::to_vec(&(prefix.to_string(), cursor.0))
        .map_err(|error| MgmtError::Operation(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
