//! Authority retained between a local observation and transport disclosure.

use super::{ConsoleError, ConsolePrincipal, ConsoleState, subscriptions::Access};
use crate::protocol::{ActionResult, ConsoleErrorCode, ConsoleFailure};
use std::sync::{Arc, Mutex};
use xolotl_kernel::host::HostDeadline;

#[derive(Default)]
pub(crate) struct DeliveryCollector(Mutex<Option<Access>>);

impl DeliveryCollector {
    pub(super) fn record(&self, access: Access) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = Some(access);
    }

    pub(super) fn take(&self) -> Option<Access> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }
}

struct Authority {
    state: Arc<ConsoleState>,
    sid: String,
    principal: ConsolePrincipal,
    access: Option<Access>,
    deadline: Option<HostDeadline>,
}

/// A bounded disclosure's current-authority check, independent of its bytes.
/// Clones share the original scope and deadline; validation does not renew the
/// session, repeat effects, or extend visibility. Adapters validate after their
/// last readiness/queue await, immediately before handing bytes to transport.
#[derive(Clone)]
pub struct ConsoleDelivery(Arc<Authority>);

impl ConsoleDelivery {
    pub(super) fn new(
        state: Arc<ConsoleState>,
        sid: String,
        principal: ConsolePrincipal,
        access: Option<Access>,
        deadline: Option<HostDeadline>,
    ) -> Self {
        Self(Arc::new(Authority {
            state,
            sid,
            principal,
            access,
            deadline,
        }))
    }

    /// Revalidate the original session, authority and disclosure deadline.
    /// Success linearizes this service-controlled disclosure, not later network
    /// receipt. Already handed-off bytes and committed effects cannot be undone.
    pub async fn validate(&self) -> Result<(), ConsoleFailure> {
        let authority = &self.0;
        let _capacity =
            super::authentication_capacity(&authority.state).map_err(ConsoleFailure::from)?;
        let current = authority
            .state
            .auth
            .validate_sid(&authority.state.boot, &authority.sid)
            .await?;
        if current != authority.principal {
            return Err(ConsoleFailure::new(
                ConsoleErrorCode::Forbidden,
                "delivery authority changed".into(),
            ));
        }
        if let Some(access) = &authority.access {
            access
                .authorize(&authority.state, &current)
                .await
                .map_err(ConsoleFailure::from)?;
        }
        if let Some(deadline) = authority.deadline {
            let elapsed =
                crate::host_time::elapsed(authority.state.boot.kernel().host_runtime(), deadline)
                    .map_err(ConsoleError::Runtime)
                    .map_err(ConsoleFailure::from)?;
            if elapsed {
                return Err(ConsoleFailure::new(
                    ConsoleErrorCode::Forbidden,
                    "output visibility expired".into(),
                ));
            }
        }
        Ok(())
    }
}

/// An action's local result with the authority needed for later disclosure.
/// Dropping this value does not roll back an accepted action. `deliver` creates
/// a local observation; network adapters retain `ConsoleDelivery` through waits.
#[must_use = "a prepared result requires current delivery authority"]
pub struct PreparedConsoleResult {
    pub(crate) result: Result<ActionResult, ConsoleFailure>,
    pub(crate) delivery: Option<ConsoleDelivery>,
}

impl PreparedConsoleResult {
    /// Obtain a local result after checking current authority. A later network
    /// disclosure needs another validation at that adapter's final handoff.
    pub async fn deliver(self) -> Result<ActionResult, ConsoleFailure> {
        if let Some(delivery) = &self.delivery
            && let Err(failure) = delivery.validate().await
        {
            return Err(withheld(failure, &self.result));
        }
        self.result
    }

    /// Separate payload and authority for an adapter. The payload is a local
    /// observation, not permission to disclose it after a subsequent await.
    pub fn into_parts(
        self,
    ) -> (
        Result<ActionResult, ConsoleFailure>,
        Option<ConsoleDelivery>,
    ) {
        (self.result, self.delivery)
    }
}

pub(crate) fn withheld(
    mut failure: ConsoleFailure,
    result: &Result<ActionResult, ConsoleFailure>,
) -> ConsoleFailure {
    match result {
        Ok(result) => {
            failure.execution = result.execution.clone();
            failure.unresolved_operations = result.unresolved_operations.clone();
        }
        Err(original) => {
            if original.code == ConsoleErrorCode::OutcomeUnknown {
                failure.code = ConsoleErrorCode::OutcomeUnknown;
                failure.message =
                    "delivery denied; accepted action outcome remains uncertain".into();
            }
            failure.execution = original.execution.clone();
            failure.unresolved_operations = original.unresolved_operations.clone();
            failure.outcome_unknown = original.outcome_unknown.clone();
            failure.finalization_error = original.finalization_error.clone();
        }
    }
    failure
}
