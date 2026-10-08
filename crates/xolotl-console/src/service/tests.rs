use super::*;
pub(crate) mod authentication;
use crate::protocol::*;
use crate::{
    BootstrapOutcome, ConsoleConfig, LoginRequest, RootProvisioning, StepUpRequest,
    bootstrap_root_account,
};
use anyhow::{Context, ensure};
use xolotl_kernel::Bootstrap;
use xolotl_standard::{StandardConfig, install_standard};

pub(crate) async fn fixture() -> anyhow::Result<(Arc<ConsoleState>, ConsoleService, String, String)>
{
    fixture_with_boot(Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    )))
    .await
}

pub(crate) async fn fixture_with_boot(
    boot: Arc<Bootstrap>,
) -> anyhow::Result<(Arc<ConsoleState>, ConsoleService, String, String)> {
    install_standard(&boot, &StandardConfig::default())?;
    let outcome = bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning::default(),
    )
    .await?;
    let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
        anyhow::bail!("bootstrap");
    };
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::new(32, 10_000)?,
                ),
            )),
            max_concurrent_calls: 1,
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state.clone());
    let login = service
        .login(
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "embedded".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("authenticated session")?;
    Ok((state, service, login.token, password))
}

fn action(action: &str, input: Value) -> ActionCall {
    ActionCall {
        action: action.into(),
        input,
        ..Default::default()
    }
}

#[tokio::test]
async fn ordinary_console_without_observations_has_no_history_contract() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let (state, service, token, _) = fixture_with_boot(boot.clone()).await?;
    ensure!(!boot.kernel().facts().is_enabled());
    let result = service
        .call(
            &token,
            None,
            action(ACTION_PROTOCOL_DESCRIBE, Value::null()),
        )
        .await?;
    ensure!(result.server_rev == 0);
    let snapshot = super::registry_snapshot(&state)?;
    ensure!(
        !snapshot
            .actions
            .iter()
            .any(|entry| entry.id == ACTION_AUDIT_FACTS_RECENT)
    );
    ensure!(
        !snapshot
            .streams
            .iter()
            .any(|entry| entry.id == STREAM_AUDIT_FACTS)
    );
    ensure!(
        snapshot
            .streams
            .iter()
            .any(|entry| entry.id == STREAM_STATE_WATCH)
    );
    let health = service
        .call(&token, None, action(ACTION_HEALTH_SUMMARY, Value::null()))
        .await?;
    let health = health.output.context("health output")?;
    let fields = health.as_map().context("health fields")?;
    ensure!(fields.get("fact_sample").is_some_and(Value::is_null));
    ensure!(fields.get("fact_cursor").is_some_and(Value::is_null));
    ensure!(boot.kernel().facts().all_facts().is_err());
    Ok(())
}

#[test]
fn uncertain_effect_keeps_host_identity_without_promoting_remote_errors() -> anyhow::Result<()> {
    use xolotl_types::Failure;

    let failure = ConsoleFailure::from(ConsoleError::Runtime(Failure::OutcomeUnknown {
        operation_ids: vec!["1/2/3/4/0".into(), "1/2/4/5/0".into()],
        reason: "delivery_or_session_lost".into(),
    }));
    ensure!(failure.code == ConsoleErrorCode::OutcomeUnknown);
    let detail = failure.outcome_unknown.as_ref().context("host detail")?;
    ensure!(detail.operation_ids == ["1/2/3/4/0", "1/2/4/5/0"]);
    ensure!(detail.reason == "delivery_or_session_lost");
    let json = serde_json::to_value(&failure)?;
    ensure!(json["code"] == "outcome_unknown");
    ensure!(
        json["outcome_unknown"]["operation_ids"] == serde_json::json!(["1/2/3/4/0", "1/2/4/5/0"])
    );

    let unclassified = ConsoleFailure::from(ConsoleError::Runtime(Failure::OutcomeUnknown {
        operation_ids: vec!["opaque-host-id".into()],
        reason: "secret diagnostic that must stay internal".into(),
    }));
    ensure!(
        unclassified
            .outcome_unknown
            .as_ref()
            .context("unknown host detail")?
            .reason
            == "unclassified"
    );
    ensure!(!unclassified.message.contains("secret diagnostic"));

    let forged = ConsoleFailure::from(ConsoleError::Runtime(Failure::HandlerError {
        kind: "outcome_unknown".into(),
        message: "operation_id=forged; reason=delivery_or_session_lost".into(),
    }));
    ensure!(forged.code == ConsoleErrorCode::Internal);
    ensure!(forged.outcome_unknown.is_none());
    ensure!(!forged.message.contains("forged"));
    Ok(())
}

#[tokio::test]
async fn embedded_service_enforces_admission_capacity_step_up_and_revocation() -> anyhow::Result<()>
{
    let (state, service, token, _) = fixture().await?;
    let read = action(ACTION_PROTOCOL_DESCRIBE, Value::null());
    ensure!(
        service
            .call("invalid", None, read.clone())
            .await
            .err()
            .context("expected rejection")?
            .code
            == ConsoleErrorCode::NotAuthenticated
    );
    let result = service.call(&token, None, read.clone()).await?;
    ensure!(result.registry_rev == state.registry.current_rev());
    let output = result.output.context("metadata")?;
    ensure!(
        output
            .as_map()
            .and_then(|m| m.get("protocol_version"))
            .and_then(Value::as_int)
            == Some(i64::from(protocol::PROTOCOL_VERSION))
    );
    let permit = state.calls.try_acquire().context("capacity")?;
    let failure = service
        .call(&token, None, read.clone())
        .await
        .err()
        .context("capacity rejection")?;
    ensure!(failure.code == ConsoleErrorCode::RateLimited);
    ensure!(failure.retry_after_ms.is_none());
    drop(permit);
    let stale = ActionCall {
        registry_rev: Some(state.registry.current_rev() ^ 1),
        ..read.clone()
    };
    let failure = service
        .call(&token, None, stale)
        .await
        .err()
        .context("stale registry")?;
    ensure!(failure.code == ConsoleErrorCode::RegistryChanged);
    ensure!(failure.current_registry_rev == Some(state.registry.current_rev()));
    let invalid = action(
        ACTION_CONFIG_READ,
        map_value([
            ("path", Value::string("state://kernel/config".into())),
            ("typo", Value::boolean(true)),
        ]),
    );
    ensure!(
        service
            .call(&token, None, invalid)
            .await
            .err()
            .context("expected rejection")?
            .code
            == ConsoleErrorCode::BadRequest
    );
    let write = action(
        ACTION_CONFIG_WRITE_CAS,
        map_value([
            ("path", Value::string("state://kernel/audit/rules".into())),
            ("value", Value::null()),
        ]),
    );
    ensure!(
        service
            .call(&token, None, write)
            .await
            .err()
            .context("expected rejection")?
            .code
            == ConsoleErrorCode::StepUpRequired
    );
    let result = service
        .call(
            &token,
            None,
            action(ACTION_ACCESS_SESSION_CURRENT_LOGOUT, Value::null()),
        )
        .await?;
    ensure!(result.output.is_none());
    ensure!(result.registry_rev == state.registry.current_rev());
    ensure!(
        service
            .call(&token, None, read)
            .await
            .err()
            .context("expected rejection")?
            .code
            == ConsoleErrorCode::NotAuthenticated
    );
    Ok(())
}

#[tokio::test]
async fn session_revocations_report_current_session_invalidation() -> anyhow::Result<()> {
    for revoke_user in [false, true] {
        let (state, service, token, _password) = fixture().await?;
        let enrolled = state.auth.enroll_test_totp(&state.boot, &token).await?;
        let elevated = service
            .step_up(
                &enrolled.token,
                StepUpRequest {
                    proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
                },
                "embedded".into(),
            )
            .await?
            .into_session()
            .ok()
            .context("stepped-up session")?;
        let authenticated = service.authenticate_session(&elevated.token).await?;
        let (action_id, input) = if revoke_user {
            (
                ACTION_ACCESS_SESSION_REVOKE_USER,
                map_value([("username", Value::string("root".into()))]),
            )
        } else {
            (
                ACTION_ACCESS_SESSION_REVOKE,
                map_value([("sid", Value::string(authenticated.sid.clone()))]),
            )
        };
        let outcome = service
            .execute_session_admitted(
                &authenticated.principal,
                &authenticated.sid,
                None,
                action(action_id, input),
                service.reserve_call()?,
            )
            .await?;
        ensure!(outcome.session_invalidated);
        let count = outcome
            .result
            .output
            .as_ref()
            .and_then(Value::as_map)
            .and_then(|value| value.get("count"))
            .and_then(Value::as_int)
            .context("revoke count")?;
        ensure!(count >= 1);
        let failure = service
            .call(
                &elevated.token,
                None,
                action(ACTION_PROTOCOL_DESCRIBE, Value::null()),
            )
            .await
            .err()
            .context("revoked bearer")?;
        ensure!(failure.code == ConsoleErrorCode::NotAuthenticated);
    }
    Ok(())
}

#[tokio::test]
async fn prepared_results_revalidate_without_breaking_self_revocation() -> anyhow::Result<()> {
    let (_, service, token, _) = fixture().await?;
    let prepared = service
        .prepare_call(
            &token,
            None,
            action(ACTION_PROTOCOL_DESCRIBE, Value::null()),
        )
        .await?;
    let logout = service
        .prepare_call(
            &token,
            None,
            action(ACTION_ACCESS_SESSION_CURRENT_LOGOUT, Value::null()),
        )
        .await?;
    ensure!(logout.deliver().await?.output.is_none());
    let denied = prepared
        .deliver()
        .await
        .err()
        .context("stale prepared result")?;
    ensure!(denied.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(denied.runtime_completion.is_none());
    Ok(())
}

#[test]
fn withheld_results_preserve_evidence_without_disclosing_completion() -> anyhow::Result<()> {
    let mut original = ConsoleFailure::new(ConsoleErrorCode::OutcomeUnknown, "uncertain".into());
    original.runtime_completion = Some(Box::new(Value::string("private body".into())));
    original.execution = Some(Box::new(ExecutionReference {
        execution_id: Some("execution-42".into()),
        process_id: "42".into(),
        program_id: "ab".repeat(32),
    }));
    let mut unresolved = xolotl_types::UnresolvedOperations::default();
    ensure!(unresolved.record("provider-ticket-42"));
    original.unresolved_operations = Some(Box::new(unresolved));
    let withheld = super::delivery::withheld(
        ConsoleFailure::new(ConsoleErrorCode::Forbidden, "revoked".into()),
        &Err(original),
    );
    ensure!(withheld.runtime_completion.is_none());
    ensure!(withheld.code == ConsoleErrorCode::OutcomeUnknown);
    ensure!(withheld.execution.context("execution")?.process_id == "42");
    ensure!(
        withheld
            .unresolved_operations
            .context("evidence")?
            .operation_ids
            == ["provider-ticket-42"]
    );
    Ok(())
}

#[tokio::test]
async fn action_and_authentication_capacity_precede_credential_state_work() -> anyhow::Result<()> {
    let (state, service, token, password) = fixture().await?;
    let read = action(ACTION_PROTOCOL_DESCRIBE, Value::null());
    let action_capacity = state.calls.try_acquire().context("action capacity")?;
    let failure = service
        .call("invalid-bearer", None, read.clone())
        .await
        .err()
        .context("saturated action capacity")?;
    ensure!(failure.code == ConsoleErrorCode::RateLimited);
    drop(action_capacity);
    ensure!(
        service
            .call("invalid-bearer", None, read.clone())
            .await
            .err()
            .context("invalid bearer after release")?
            .code
            == ConsoleErrorCode::NotAuthenticated
    );

    let auth_capacity = state
        .authentications
        .try_acquire_many(u32::try_from(state.authentications.available_permits())?)
        .context("authentication capacity")?;
    let failure = service
        .login(
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "embedded".into(),
        )
        .await
        .err()
        .context("saturated authentication capacity")?;
    ensure!(failure.code == ConsoleErrorCode::RateLimited);
    let failure = service
        .call(&token, None, read.clone())
        .await
        .err()
        .context("action bearer check shares authentication capacity")?;
    ensure!(failure.code == ConsoleErrorCode::RateLimited);
    drop(auth_capacity);
    service.call(&token, None, read).await?;
    ensure!(
        service
            .login(
                LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "embedded".into(),
            )
            .await?
            .into_session()
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn embedded_refresh_preserves_session_limits_and_records_verified_source()
-> anyhow::Result<()> {
    let (state, service, token, _password) = fixture().await?;
    let enrolled = state.auth.enroll_test_totp(&state.boot, &token).await?;
    let elevated = service
        .step_up(
            &enrolled.token,
            StepUpRequest {
                proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
            },
            "embedded".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("stepped-up session")?;
    let refreshed = service
        .refresh(&elevated.token, "refresh-peer".into())
        .await?;
    ensure!(refreshed.sid == elevated.sid);
    ensure!(refreshed.authentication == elevated.authentication);
    ensure!(
        refreshed.authentication.mfa_level() == elevated.authentication.mfa_level()
            && refreshed.authentication.mfa_level() == 2
    );
    ensure!(refreshed.expires_at == elevated.expires_at);
    ensure!(refreshed.idle_expires_at >= elevated.idle_expires_at);
    ensure!(refreshed.token != elevated.token);
    let expected_evidence = elevated.authentication.to_value();
    let authority = service
        .call(
            &refreshed.token,
            None,
            action(ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE, Value::null()),
        )
        .await?
        .output
        .context("effective principal")?;
    ensure!(
        authority.as_map().and_then(|map| map.get("authentication")) == Some(&expected_evidence)
    );
    let sessions = service
        .call(
            &refreshed.token,
            None,
            action(ACTION_ACCESS_SESSION_LIST, Value::null()),
        )
        .await?
        .output
        .context("session page")?;
    let row = sessions
        .as_map()
        .and_then(|map| map.get("entries"))
        .and_then(Value::as_list)
        .context("session entries")?
        .iter()
        .filter_map(Value::as_map)
        .find(|row| row.get("sid").and_then(Value::as_str) == Some(refreshed.sid.as_str()))
        .context("refreshed session projection")?;
    ensure!(row.get("authentication") == Some(&expected_evidence));
    ensure!(
        row.get("authenticated_at").and_then(Value::as_int)
            == elevated.authentication.authenticated_at()
    );
    let read = action(ACTION_PROTOCOL_DESCRIBE, Value::null());
    service.call(&refreshed.token, None, read.clone()).await?;
    let old = service
        .call(&elevated.token, None, read)
        .await
        .err()
        .context("old bearer")?;
    ensure!(old.code == ConsoleErrorCode::NotAuthenticated);
    let facts = state.boot.kernel().facts().all_facts()?;
    let audits: Vec<_> = facts
        .iter()
        .filter_map(|f| f.outcome.as_ref()?.as_map())
        .filter(|m| {
            m.get("event").and_then(Value::as_str) == Some("console_credential")
                && m.get("outcome").and_then(Value::as_str) == Some("token_refresh")
        })
        .collect();
    ensure!(audits.len() == 1);
    ensure!(audits[0].get("source_addr").and_then(Value::as_str) == Some("refresh-peer"));
    ensure!(audits[0].get("username").and_then(Value::as_str) == Some("root"));
    ensure!(audits[0].get("mfa_level").is_none());
    ensure!(
        audits[0]
            .get("details")
            .and_then(Value::as_map)
            .and_then(|details| details.get("authentication"))
            .and_then(Value::as_map)
            .and_then(|authentication| authentication.get("mfa_level"))
            .and_then(Value::as_int)
            == Some(2)
    );
    let audit_json = serde_json::to_string(&Value::from(audits[0].clone()))?;
    ensure!(!audit_json.contains(&refreshed.token));
    ensure!(!audit_json.contains(&elevated.token));
    service
        .call(
            &refreshed.token,
            None,
            action(ACTION_ACCESS_SESSION_CURRENT_LOGOUT, Value::null()),
        )
        .await?;
    let failure = service
        .refresh(&refreshed.token, "refresh-peer".into())
        .await
        .err()
        .context("revoked refresh")?;
    ensure!(failure.code == ConsoleErrorCode::NotAuthenticated);
    Ok(())
}

#[tokio::test]
async fn visibility_pages_forward_budgets_and_reject_a_cursor_from_another_prefix()
-> anyhow::Result<()> {
    let (state, service, token, _password) = fixture().await?;
    for id in 0..5 {
        state
            .state
            .write_set(
                &Path::parse(&format!("state://app/page/{id}"))?,
                Value::integer(id),
            )
            .await?;
    }
    let token = state
        .auth
        .enroll_test_totp(&state.boot, &token)
        .await?
        .token;
    let mut cursor = None;
    let mut seen = Vec::new();
    for _ in 0..8 {
        let mut fields = BTreeMap::from([
            ("prefix".into(), Value::string("state://app/page".into())),
            ("limit".into(), Value::integer(2)),
        ]);
        if let Some(cursor) = cursor {
            fields.insert("cursor".into(), cursor);
        }
        let call = ActionCall {
            scope: Some("inspect page".into()),
            justification: Some("test bounded visibility".into()),
            ttl_ms: Some(60_000),
            ..action(ACTION_VISIBILITY_STATE_LIST, Value::map(fields))
        };
        let output = service
            .call(&token, None, call)
            .await?
            .output
            .context("page")?;
        let page = output.as_map().context("page map")?;
        let rows = page
            .get("entries")
            .and_then(Value::as_list)
            .context("entries")?;
        ensure!(rows.len() <= 2);
        seen.extend(
            rows.iter()
                .filter_map(|v| v.as_map()?.get("path")?.as_str().map(str::to_owned)),
        );
        cursor = page.get("next_cursor").filter(|v| !v.is_null()).cloned();
        if seen.len() == 2 {
            let invalid = ActionCall {
                scope: Some("inspect page".into()),
                justification: Some("test scope".into()),
                ttl_ms: Some(60_000),
                ..action(
                    ACTION_VISIBILITY_STATE_LIST,
                    map_value([
                        ("prefix", Value::string("state://app/other".into())),
                        ("cursor", cursor.clone().context("continuation")?),
                    ]),
                )
            };
            ensure!(
                service
                    .call(&token, None, invalid)
                    .await
                    .err()
                    .context("expected rejection")?
                    .code
                    == ConsoleErrorCode::BadRequest
            );
        }
        if cursor.is_none() {
            break;
        }
    }
    ensure!(seen.len() == 5);
    seen.sort();
    seen.dedup();
    ensure!(seen.len() == 5);
    Ok(())
}

#[tokio::test]
async fn session_list_is_a_bounded_page_and_does_not_sweep_expired_rows() -> anyhow::Result<()> {
    let (state, service, _token, password) = fixture().await?;
    let mut expiring_sid = None;
    let mut active_token = None;
    for index in 0..3 {
        let session = service
            .login(
                LoginRequest {
                    username: "root".into(),
                    password: password.clone(),
                    second_factor: None,
                },
                format!("source-{index}"),
            )
            .await?
            .into_session()
            .ok()
            .context("authenticated session")?;
        if expiring_sid.is_none() {
            expiring_sid = Some(
                bearer_sid(Some(&session.token))
                    .context("new session SID")?
                    .to_owned(),
            );
        }
        active_token = Some(session.token);
    }
    let expiring_sid = expiring_sid.context("new session SID")?;
    let active_token = active_token.context("active session token")?;
    ensure!(
        Some(expiring_sid.as_str()) != bearer_sid(Some(&active_token)),
        "the test must expire another session"
    );
    let value = state
        .auth
        .session_store
        .get(&expiring_sid)
        .await?
        .map(|row| row.record.to_value());
    let mut value = value
        .context("another session")?
        .into_map()
        .context("session map")?;
    value.insert("expires_at".into(), Value::integer(1))?;
    value.insert("idle_expires_at".into(), Value::integer(1))?;
    let row = crate::session_store::ConsoleSession::decode(
        &expiring_sid,
        &serde_json::to_vec(&Value::from(value))?,
    )?;
    state.auth.session_store.delete(&expiring_sid, None).await?;
    state.auth.session_store.create(row).await?;
    let output = service
        .call(
            &active_token,
            None,
            action(
                ACTION_ACCESS_SESSION_LIST,
                map_value([("limit", Value::integer(1))]),
            ),
        )
        .await
        .context("list sessions with original token")?
        .output
        .context("page")?;
    let page = output.as_map().context("page map")?;
    ensure!(
        page.get("entries")
            .and_then(Value::as_list)
            .is_some_and(|rows| rows.len() <= 1)
    );
    ensure!(page.get("next_cursor").is_some_and(|v| !v.is_null()));
    ensure!(
        state.auth.session_store.get(&expiring_sid).await?.is_some(),
        "listing must not delete expired records"
    );
    Ok(())
}

#[tokio::test]
async fn metadata_pages_compose_without_fact_visibility_and_sensitive_expansion_keeps_its_gate()
-> anyhow::Result<()> {
    let (_, service, token, _) = fixture().await?;
    let result = service
        .call(
            &token,
            None,
            action(
                ACTION_RUNTIME_PROCESS_INSPECT,
                map_value([("limit", Value::integer(1))]),
            ),
        )
        .await?;
    let output = result.output.context("page")?;
    let entries = output
        .as_map()
        .and_then(|m| m.get("entries"))
        .and_then(Value::as_list)
        .context("entries")?;
    ensure!(entries.len() == 1);
    ensure!(
        entries
            .first()
            .and_then(Value::as_map)
            .is_some_and(|m| !m.contains_key("children") && m.contains_key("child_count"))
    );
    let denied = service
        .call(
            &token,
            None,
            action(
                ACTION_RUNTIME_PROCESS_INSPECT,
                map_value([
                    ("process", Value::string("1".into())),
                    ("include_recent_facts", Value::boolean(true)),
                ]),
            ),
        )
        .await
        .err()
        .context("expansion must require step-up")?;
    ensure!(denied.code == ConsoleErrorCode::StepUpRequired);
    Ok(())
}
