//! Session authentication and admitted operations shared by service clients and adapters.

use super::*;

/// Session mutations live beside bearer validation because they may invalidate
/// the caller that entered through this service or a stateful adapter.
pub(super) async fn dispatch_action(
    context: &actions::ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<Option<Execution>, ConsoleError> {
    let result = match call.action.as_str() {
        protocol::ACTION_ACCESS_SESSION_CURRENT_LOGOUT => {
            context
                .state
                .auth
                .logout_sid_from_source(
                    &context.state.boot,
                    context.session_id,
                    context.source_addr,
                )
                .await?;
            Execution {
                result: ActionResult::empty(
                    server_rev_hint(context.state),
                    registry_rev(context.state),
                ),
                delivery: None,
                session_invalidated: true,
            }
        }
        protocol::ACTION_ACCESS_SESSION_REVOKE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let sid = string_arg(&mut input, "sid")?;
            require_step_up(principal)?;
            context
                .state
                .auth
                .revoke_session_by_id_from_source(
                    &context.state.boot,
                    principal,
                    &sid,
                    context.source_addr,
                )
                .await?;
            Execution {
                result: ActionResult::value(
                    map_value([("count", Value::integer(1))]),
                    server_rev_hint(context.state),
                    registry_rev(context.state),
                ),
                delivery: None,
                session_invalidated: context.session_id == sid,
            }
        }
        protocol::ACTION_ACCESS_SESSION_REVOKE_USER => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            require_step_up(principal)?;
            let count = context
                .state
                .auth
                .revoke_user_sessions_from_source(
                    &context.state.boot,
                    principal,
                    &username,
                    context.source_addr,
                )
                .await?;
            Execution {
                result: ActionResult::value(
                    map_value([("count", Value::integer(count as i64))]),
                    server_rev_hint(context.state),
                    registry_rev(context.state),
                ),
                delivery: None,
                session_invalidated: principal.username == username,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}

/// Fresh authority and session identity established from one bearer token.
pub(crate) struct AuthenticatedSession {
    /// Authority resolved from the bearer at this authentication boundary.
    pub(crate) principal: ConsolePrincipal,
    /// Session identifier bound to that bearer.
    pub(crate) sid: String,
}

impl ConsoleService {
    /// Authenticate a bearer before any service call or connection uses its session.
    pub(crate) async fn authenticate_session(
        &self,
        bearer: &str,
    ) -> Result<AuthenticatedSession, ConsoleError> {
        let _capacity = authentication_capacity(&self.state)?;
        let principal = self
            .state
            .auth
            .authenticate_token(&self.state.boot, bearer)
            .await?;
        drop(_capacity);
        let sid = bearer_sid(Some(bearer))
            .ok_or(ConsoleError::NotAuthenticated)?
            .to_owned();
        Ok(AuthenticatedSession { principal, sid })
    }

    /// Refresh an interactive session before an incoming frame is admitted.
    #[cfg(feature = "http")]
    pub(crate) async fn touch_session(&self, sid: &str) -> Result<ConsolePrincipal, ConsoleError> {
        let _capacity = authentication_capacity(&self.state)?;
        self.state
            .auth
            .authenticate_sid(&self.state.boot, sid)
            .await
            .map_err(Into::into)
    }

    /// Check a session before delivering an already accepted event.
    #[cfg(feature = "http")]
    pub(crate) async fn validate_session(
        &self,
        sid: &str,
    ) -> Result<ConsolePrincipal, ConsoleError> {
        let _capacity = authentication_capacity(&self.state)?;
        self.state
            .auth
            .validate_sid(&self.state.boot, sid)
            .await
            .map_err(Into::into)
    }

    /// Reserve an action slot before session revalidation and call dispatch.
    pub(crate) fn reserve_call(&self) -> Result<CallAdmission, ConsoleError> {
        call_capacity(&self.state)
    }

    /// Execute an admitted call under freshly validated session authority.
    /// The caller retains the permit from before revalidation through dispatch.
    #[cfg(test)]
    pub(crate) async fn execute_session_admitted(
        &self,
        principal: &ConsolePrincipal,
        sid: &str,
        source: Option<&str>,
        call: ActionCall,
        capacity: CallAdmission,
    ) -> Result<Execution, ConsoleError> {
        let context = actions::ActionContext {
            delivery: None,
            state: &self.state,
            source_addr: source,
            session_id: sid,
        };
        execute_admitted(&context, principal, call, capacity).await
    }

    #[cfg(feature = "http")]
    pub(crate) async fn prepare_session_admitted(
        &self,
        principal: &ConsolePrincipal,
        sid: &str,
        source: Option<&str>,
        call: ActionCall,
        capacity: CallAdmission,
    ) -> Result<(PreparedConsoleResult, bool), ConsoleError> {
        let collector = delivery::DeliveryCollector::default();
        let deadline = call
            .ttl_ms
            .map(|ttl| {
                crate::host_time::after(
                    self.state.boot.kernel().host_runtime(),
                    std::time::Duration::from_millis(ttl),
                )
                .map_err(ConsoleError::Runtime)
            })
            .transpose()?;
        let context = actions::ActionContext {
            state: &self.state,
            source_addr: source,
            session_id: sid,
            delivery: Some(&collector),
        };
        match execute_admitted(&context, principal, call, capacity).await {
            Ok(execution) => Ok((
                PreparedConsoleResult {
                    result: Ok(execution.result),
                    delivery: execution.delivery,
                },
                execution.session_invalidated,
            )),
            Err(error) => {
                record_console_error_audit(&self.state, Some(principal), source, &error);
                let invalidated = error.session_invalidated();
                Ok((
                    PreparedConsoleResult {
                        result: Err(error.into()),
                        delivery: (!invalidated).then(|| {
                            ConsoleDelivery::new(
                                Arc::clone(&self.state),
                                sid.to_owned(),
                                principal.clone(),
                                collector.take(),
                                deadline,
                            )
                        }),
                    },
                    invalidated,
                ))
            }
        }
    }

    /// Open a stream under freshly validated session authority.
    #[cfg(feature = "http")]
    pub(crate) async fn open_session_subscription(
        &self,
        principal: &ConsolePrincipal,
        sid: &str,
        source: Option<&str>,
        stream: StreamCall,
    ) -> Result<ConsoleSubscription, ConsoleError> {
        subscriptions::open(&self.state, principal, sid, source, stream, None).await
    }
}
