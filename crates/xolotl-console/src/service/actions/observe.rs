//! Read-only Console observations and bounded projections.

use super::super::{
    ConsoleError, VisibilityAuditDetails, authorize_fact_read, ensure_observable_state_path,
    entries_value, facts, input_map, input_value, list_request, map_value, optional_bool_arg,
    optional_usize_arg, record_visibility_audit, registry_counts_value, registry_rev,
    require_process_inspect, require_visibility_access, serde_value, server_rev, sessions_value,
    string_arg,
};
use super::ActionContext;
use crate::auth::{self, ConsolePrincipal};
use crate::mgmt;
use crate::protocol::{self, ActionCall};
use crate::recipes::{self, StateMethod as RecipeStateMethod};
use std::collections::BTreeMap;
use xolotl_types::{Path, ProcessId, Value, ValueMap};

pub(super) async fn snapshot(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<Value, ConsoleError> {
    let mut input = input_map(input_value(&call.input)?)?;
    let sections = match input.remove("sections") {
        Some(value) => value.into_list().ok_or_else(|| {
            ConsoleError::BadRequest("sections must be a list of section maps".into())
        })?,
        None => vec![
            map_value([("kind", Value::string("sessions".into()))]),
            map_value([
                ("kind", Value::string("runtime".into())),
                ("limit", Value::integer(64)),
            ]),
        ]
        .into(),
    };

    if sections.len() > protocol::MAX_SNAPSHOT_SECTIONS as usize {
        return Err(ConsoleError::BadRequest(
            "snapshot accepts at most 16 sections".into(),
        ));
    }
    let mut truncated = Vec::new();
    let mut out = BTreeMap::new();
    out.insert(
        "server_rev".into(),
        Value::integer(server_rev(context.state)? as i64),
    );
    out.insert(
        "registry_rev".into(),
        Value::integer(registry_rev(context.state) as i64),
    );
    out.insert("fact_cursor".into(), observation_cursor(context.state)?);
    for section in &sections {
        let mut section = input_map(section.clone())?;
        let kind = string_arg(&mut section, "kind")?;
        match kind.as_str() {
            "kernel_config" => {
                let prefix = string_arg(&mut section, "prefix")?;
                if out.contains_key(&prefix) {
                    return Err(ConsoleError::BadRequest("duplicate config section".into()));
                }
                let mut request = list_request(&Value::from(section))?;
                let section_bytes = context.state.queries.max_page_bytes / sections.len().max(1);
                request.max_bytes = Some(
                    request
                        .max_bytes
                        .unwrap_or(section_bytes)
                        .min(section_bytes),
                );
                let entries =
                    mgmt::inspect_prefix(context.state, principal, Path::parse(&prefix)?, request)
                        .await?;
                if entries.next_cursor.is_some() {
                    truncated.push(Value::string(prefix.clone()));
                }
                out.insert(prefix, entries_value(entries));
            }
            "sessions" => {
                if out.contains_key("sessions") {
                    return Err(ConsoleError::BadRequest(
                        "duplicate sessions section".into(),
                    ));
                }
                let mut request = list_request(&Value::from(section))?;
                let section_bytes = context.state.queries.max_page_bytes / sections.len().max(1);
                request.max_bytes = Some(
                    request
                        .max_bytes
                        .unwrap_or(section_bytes)
                        .min(section_bytes),
                );
                let page = session_list(context, principal, request).await?;
                if page
                    .as_map()
                    .and_then(|m| m.get("next_cursor"))
                    .is_some_and(|v| !v.is_null())
                {
                    truncated.push(Value::string("sessions".into()));
                }
                out.insert("sessions".into(), page);
            }
            "runtime" => {
                if out.contains_key("runtime") {
                    return Err(ConsoleError::BadRequest(
                        "runtime snapshot section may be requested only once".into(),
                    ));
                }
                let include_recent_facts = section
                    .get("include_recent_facts")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if include_recent_facts {
                    require_visibility_access(principal, call)?;
                    record_visibility_audit(
                        context.state,
                        principal,
                        context.source_addr,
                        "state_snapshot_runtime_facts",
                        VisibilityAuditDetails::action(call, Some("runtime.processes")),
                    )?;
                }
                let section_bytes = context.state.queries.max_page_bytes / sections.len().max(1);
                let requested = optional_usize_arg(&mut section, "max_bytes")?
                    .unwrap_or(section_bytes)
                    .min(section_bytes);
                section
                    .insert("max_bytes".into(), Value::integer(requested as i64))
                    .map_err(|e| ConsoleError::BadRequest(e.to_string()))?;
                let runtime = process_inspect(context, principal, Value::from(section)).await?;
                if runtime
                    .as_map()
                    .and_then(|m| m.get("next_cursor"))
                    .is_some_and(|v| !v.is_null())
                {
                    truncated.push(Value::string("runtime".into()));
                }
                out.insert("runtime".into(), runtime);
            }
            other => {
                return Err(ConsoleError::BadRequest(format!(
                    "unknown snapshot section kind: {other}"
                )));
            }
        }
    }
    out.insert("truncated".into(), Value::list(truncated));
    Ok(Value::map(out))
}

pub(super) async fn visibility_state_read(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<Value, ConsoleError> {
    let path = Path::parse(path)?;
    ensure_observable_state_path(&path)?;
    auth::authorize_path(&context.state.state, principal, "read", &path, None).await?;
    run_state_op(context, principal, path, "read", Value::null()).await
}

pub(super) async fn session_list(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    request: mgmt::ListRequest,
) -> Result<Value, ConsoleError> {
    let query = mgmt::state_scan(
        &context.state.queries,
        Path::parse(auth::SESSIONS_PREFIX)?,
        request,
    )?;
    let page = context
        .state
        .auth
        .list_sessions(&context.state.boot, principal, &query)
        .await?;
    let next = page
        .next
        .map(|cursor| mgmt::encode_cursor(&query.prefix, cursor))
        .transpose()?;
    Ok(map_value([
        ("entries", sessions_value(&page.entries)),
        (
            "next_cursor",
            next.map(Value::string).unwrap_or(Value::null()),
        ),
    ]))
}

pub(super) async fn visibility_state_list(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    prefix: &str,
    request: mgmt::ListRequest,
) -> Result<Value, ConsoleError> {
    let prefix = Path::parse(prefix)?;
    ensure_observable_state_path(&prefix)?;
    auth::authorize_prefix_read(&context.state.state, principal, &prefix).await?;
    let query = mgmt::state_scan(&context.state.queries, prefix.clone(), request)?;
    let input = map_value([
        ("limit", Value::integer(query.limits.entries.get() as i64)),
        (
            "max_examined",
            Value::integer(query.limits.examined.get() as i64),
        ),
        (
            "max_encoded_bytes",
            Value::integer(query.limits.encoded_bytes.get() as i64),
        ),
        (
            "cursor",
            query
                .cursor
                .as_ref()
                .map(|c| Value::bytes(c.0.clone()))
                .unwrap_or(Value::null()),
        ),
    ]);
    let output = run_state_op(context, principal, prefix.clone(), "list", input).await?;
    let map = output
        .as_map()
        .ok_or_else(|| ConsoleError::Operation("invalid state page".into()))?;
    let entries = map
        .get("entries")
        .filter(|v| v.as_list().is_some())
        .ok_or_else(|| ConsoleError::Operation("invalid state page entries".into()))?;
    for entry in entries
        .as_list()
        .ok_or_else(|| ConsoleError::Operation("invalid state page entries".into()))?
    {
        let path = entry
            .as_map()
            .and_then(|record| record.get("path"))
            .and_then(Value::as_str)
            .ok_or_else(|| ConsoleError::Operation("invalid state page path".into()))?;
        let path = Path::parse(path)?;
        if path != prefix && !prefix.is_prefix_of(&path) {
            return Err(ConsoleError::Operation(
                "state page path is outside its prefix".into(),
            ));
        }
        auth::authorize_path(&context.state.state, principal, "read", &path, None).await?;
    }
    let next = match map.get("next") {
        Some(value) if value.is_null() => None,
        Some(value) => Some(xolotl_state::StateCursor(
            value
                .as_bytes()
                .ok_or_else(|| ConsoleError::Operation("invalid state cursor".into()))?
                .to_vec(),
        )),
        None => {
            return Err(ConsoleError::Operation(
                "state page is missing continuation".into(),
            ));
        }
    };
    if next.is_some() && next == query.cursor {
        return Err(ConsoleError::Operation(
            "state cursor did not advance".into(),
        ));
    }
    Ok(map_value([
        ("entries", entries.clone()),
        (
            "next_cursor",
            next.map(|c| mgmt::encode_cursor(&prefix, c))
                .transpose()?
                .map(Value::string)
                .unwrap_or(Value::null()),
        ),
    ]))
}

async fn run_state_op(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    path: Path,
    method: &str,
    input: Value,
) -> Result<Value, ConsoleError> {
    let state_method = match method {
        "read" => RecipeStateMethod::Read,
        "list" => RecipeStateMethod::List,
        "write" => RecipeStateMethod::Write,
        "append" => RecipeStateMethod::Append,
        "delete" => RecipeStateMethod::Delete,
        other => {
            return Err(ConsoleError::Operation(format!(
                "unsupported state method: {other}"
            )));
        }
    };
    let compiled = recipes::CompiledRecipe::state(path, state_method, input)
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    recipes::execute(context.state, principal, compiled).await
}

pub(crate) async fn process_inspect(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    input: Value,
) -> Result<Value, ConsoleError> {
    require_process_inspect(principal)?;
    let mut input = input_map(input)?;
    let process = facts::optional_cursor_arg(&mut input, "process")?;
    let after = facts::optional_cursor_arg(&mut input, "cursor")?;
    let include_recent_facts =
        optional_bool_arg(&mut input, "include_recent_facts")?.unwrap_or(false);
    let limit = optional_usize_arg(&mut input, "limit")?
        .unwrap_or(64)
        .min(context.state.queries.max_process_limit);
    let limit = std::num::NonZeroUsize::new(limit)
        .ok_or_else(|| ConsoleError::BadRequest("limit must be positive".into()))?;
    let bytes = facts::byte_limit(
        &context.state.queries,
        optional_usize_arg(&mut input, "max_bytes")?,
    )?
    .get();
    if process.is_some() && after.is_some() {
        return Err(ConsoleError::BadRequest(
            "process and cursor are mutually exclusive".into(),
        ));
    }
    if include_recent_facts {
        if process.is_none() {
            return Err(ConsoleError::BadRequest(
                "include_recent_facts requires an explicit process".into(),
            ));
        }
        authorize_fact_read(principal, process)?;
    }
    let fact_limit = optional_usize_arg(&mut input, "fact_limit")?;
    if fact_limit.is_some() && !include_recent_facts {
        return Err(ConsoleError::BadRequest(
            "fact_limit requires include_recent_facts".into(),
        ));
    }
    let processes = context.state.boot.kernel().processes();
    let (observations, mut next) = if let Some(id) = process {
        (
            vec![(ProcessId::new(id), processes.observe(ProcessId::new(id)))],
            None,
        )
    } else {
        let page = processes.observe_page(after.map(ProcessId::new), limit);
        (
            page.entries
                .into_iter()
                .map(|r| (r.process, Some(r)))
                .collect(),
            page.next,
        )
    };
    let mut rows = Vec::new();
    let mut encoded = 0;
    let mut last = None;
    for (id, observed) in observations {
        let mut row = BTreeMap::from([("process".into(), facts::cursor_value(id.get()))]);
        if let Some(observed) = observed {
            row.insert(
                "status".into(),
                Value::string(format!("{:?}", observed.status)),
            );
            row.insert(
                "terminal".into(),
                Value::boolean(observed.status.is_terminal()),
            );
            row.insert(
                "identity".into(),
                facts::cursor_value(observed.identity.get()),
            );
            row.insert(
                "parent".into(),
                observed
                    .parent
                    .map(|p| facts::cursor_value(p.get()))
                    .unwrap_or(Value::null()),
            );
            row.insert(
                "child_count".into(),
                Value::integer(observed.child_count as i64),
            );
        } else {
            row.insert("status".into(), Value::string("Unknown".into()));
        }
        if include_recent_facts {
            let mut fields = ValueMap::from(BTreeMap::from([
                (
                    "limit".into(),
                    Value::integer(fact_limit.unwrap_or(64) as i64),
                ),
                (
                    "max_bytes".into(),
                    Value::integer((bytes / 8).max(1) as i64),
                ),
            ]));
            let query = facts::query(
                &context.state.queries,
                facts::ReadKind::Recent,
                Some(id.get()),
                &mut fields,
            )?;
            row.insert(
                "recent_facts".into(),
                facts::read_page(
                    context.state.boot.kernel().facts(),
                    query,
                    facts::ReadKind::Recent,
                )?,
            );
        }
        let row = Value::map(row);
        let size = serde_json::to_vec(&row)
            .map_err(|e| ConsoleError::Operation(e.to_string()))?
            .len();
        if encoded + size > bytes {
            if rows.is_empty() {
                return Err(ConsoleError::BadRequest(
                    "process record exceeds max_bytes".into(),
                ));
            }
            next = last;
            break;
        }
        encoded += size;
        rows.push(row);
        last = Some(id);
    }
    Ok(map_value([
        ("entries", Value::list(rows)),
        (
            "next_cursor",
            next.map(|p| facts::cursor_value(p.get()))
                .unwrap_or(Value::null()),
        ),
    ]))
}

pub(super) async fn health_summary(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
) -> Result<Value, ConsoleError> {
    let kernel_path = Path::parse("state://kernel")?;
    auth::authorize_path(&context.state.state, principal, "read", &kernel_path, None).await?;

    let registry = registry_counts_value(context.state.boot.kernel().registry().counts());
    Ok(map_value([
        ("status", Value::string("ok".into())),
        (
            "server_rev",
            Value::integer(server_rev(context.state)? as i64),
        ),
        (
            "registry_rev",
            Value::integer(registry_rev(context.state) as i64),
        ),
        (
            "process_count",
            Value::integer(context.state.boot.kernel().processes().len() as i64),
        ),
        (
            "fact_sample",
            if context.state.boot.kernel().facts().is_enabled() {
                facts::sample(context.state.boot.kernel().facts(), &context.state.queries)?
            } else {
                Value::null()
            },
        ),
        ("fact_cursor", observation_cursor(context.state)?),
        ("registry", registry),
        ("query_limits", serde_value(&context.state.queries)?),
    ]))
}

fn observation_cursor(state: &crate::ConsoleState) -> Result<Value, ConsoleError> {
    let sink = state.boot.kernel().facts();
    if !sink.is_enabled() {
        return Ok(Value::null());
    }
    Ok(facts::cursor_value(sink.observed_cursor()?))
}
