//! Audited state, Fact and process observations.

use super::*;

pub(super) async fn dispatch(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let out = match call.action.as_str() {
        ACTION_VISIBILITY_AUTHORITY_DESCRIBE => protocol::visibility_authority_value(),
        ACTION_SECRET_CATALOG => protocol::secret_catalog_value(),
        ACTION_VISIBILITY_STATE_READ => {
            require_visibility_access(principal, call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let path = string_arg(&mut input, "path")?;
            if let Err(e) = ensure_observable_state_path_str(&path) {
                let target = blocked_visibility_target(&path);
                record_visibility_audit(
                    context.state,
                    principal,
                    context.source_addr,
                    "state_read_blocked",
                    VisibilityAuditDetails::action(call, Some(&target)),
                )?;
                return Err(e);
            }
            record_visibility_audit(
                context.state,
                principal,
                context.source_addr,
                "state_read",
                VisibilityAuditDetails::action(call, Some(&path)),
            )?;
            visibility_state_read(context, principal, &path).await?
        }
        ACTION_VISIBILITY_STATE_LIST => {
            require_visibility_access(principal, call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let prefix = string_arg(&mut input, "prefix")?;
            if let Err(e) = ensure_observable_state_path_str(&prefix) {
                let target = blocked_visibility_target(&prefix);
                record_visibility_audit(
                    context.state,
                    principal,
                    context.source_addr,
                    "state_list_blocked",
                    VisibilityAuditDetails::action(call, Some(&target)),
                )?;
                return Err(e);
            }
            record_visibility_audit(
                context.state,
                principal,
                context.source_addr,
                "state_list",
                VisibilityAuditDetails::action(call, Some(&prefix)),
            )?;
            visibility_state_list(context, principal, &prefix, list_request(&call.input)?).await?
        }
        ACTION_STATE_SNAPSHOT => snapshot(context, principal, call).await?,
        ACTION_RUNTIME_PROCESS_INSPECT => {
            let mut input = input_map(input_value(&call.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?;
            if optional_bool_arg(&mut input, "include_recent_facts")?.unwrap_or(false) {
                require_visibility_access(principal, call)?;
                let target = process.map(|pid| format!("process:{pid}"));
                record_visibility_audit(
                    context.state,
                    principal,
                    context.source_addr,
                    "runtime_process_inspect",
                    VisibilityAuditDetails::action(call, target.as_deref()),
                )?;
            }
            process_inspect(context, principal, call.input.clone()).await?
        }
        ACTION_AUDIT_FACTS_RECENT => {
            require_visibility_access(principal, call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?;
            authorize_fact_read(principal, process)?;
            let query = facts::query(
                &context.state.queries,
                facts::ReadKind::Recent,
                process,
                &mut input,
            )?;
            let target = process
                .map(|pid| fact_path(pid).map(|path| path.to_string()))
                .transpose()?
                .unwrap_or_else(|| "state://fact".into());
            record_visibility_audit(
                context.state,
                principal,
                context.source_addr,
                "audit_facts_recent",
                VisibilityAuditDetails::action(call, Some(&target)),
            )?;
            facts::read_page(
                context.state.boot.kernel().facts(),
                query,
                facts::ReadKind::Recent,
            )?
        }
        ACTION_LINEAGE_TRACE_READ => {
            require_visibility_access(principal, call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?
                .ok_or_else(|| ConsoleError::BadRequest("process is required".into()))?;
            authorize_fact_read(principal, Some(process))?;
            let query = facts::query(
                &context.state.queries,
                facts::ReadKind::Trace,
                Some(process),
                &mut input,
            )?;
            let target = fact_path(process)?.to_string();
            record_visibility_audit(
                context.state,
                principal,
                context.source_addr,
                "lineage_trace_read",
                VisibilityAuditDetails::action(call, Some(&target)),
            )?;
            facts::read_page(
                context.state.boot.kernel().facts(),
                query,
                facts::ReadKind::Trace,
            )?
        }
        ACTION_LINEAGE_FACT_READ => {
            require_visibility_access(principal, call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let op_id = parse_operation_id(&string_arg(&mut input, "op_id")?)?;
            let process =
                facts::optional_cursor_arg(&mut input, "process")?.unwrap_or(op_id.process.get());
            authorize_fact_read(principal, Some(process))?;
            let max_bytes = facts::byte_limit(
                &context.state.queries,
                optional_usize_arg(&mut input, "max_bytes")?,
            )?;
            record_visibility_audit(
                context.state,
                principal,
                context.source_addr,
                "lineage_fact_read",
                VisibilityAuditDetails::action(call, Some(&format!("operation:{op_id}"))),
            )?;
            facts::read_detail(
                context.state.boot.kernel().facts(),
                xolotl_kernel::FactLookup {
                    id: op_id,
                    process: Some(ProcessId::new(process)),
                    max_encoded_bytes: max_bytes,
                },
            )?
        }
        ACTION_HEALTH_SUMMARY => health_summary(context, principal).await?,
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
