//! Reservation ownership for the hosted invocation boundary.

use crate::invocation::{AccountCompletion, AccountPermit, Billing, Charge, Settlement};
use crate::process::ProcessTable;
use core::future::{Ready, ready};
use xolotl_types::{DriverOutput, Failure, MethodContract, Operation, ProcessId};

#[derive(Debug, thiserror::Error)]
#[error("{failure}")]
pub(super) struct DispatchFailure {
    pub failure: Failure,
    pub may_have_started: bool,
}

impl DispatchFailure {
    fn known(failure: Failure) -> Self {
        Self {
            failure,
            may_have_started: false,
        }
    }

    fn uncertain(failure: Failure) -> Self {
        Self {
            failure,
            may_have_started: true,
        }
    }
}

pub(super) struct Reservation {
    billing: Billing,
    inner: Option<crate::invocation::Reservation<ProcessPermit>>,
}

impl Reservation {
    pub fn reserve(
        processes: &ProcessTable,
        op: &Operation,
        contract: MethodContract,
        _target: Option<&xolotl_types::Path>,
    ) -> Result<Self, Failure> {
        let billing = Billing::new(&op.input, contract);
        let charge = billing.reservation();
        processes
            .reserve(op.process, charge.micro_usd, charge.tokens)
            .map_err(|dim| Failure::BudgetExhausted { dim })?;
        Ok(Self {
            billing,
            inner: Some(crate::invocation::Reservation::new(
                ProcessPermit {
                    processes: processes.clone(),
                    process: op.process,
                },
                op.id,
                charge,
            )),
        })
    }

    pub fn dispatched(&mut self) -> Result<(), DispatchFailure> {
        let Some(inner) = self.inner.as_mut() else {
            return Err(DispatchFailure::uncertain(owner_unavailable()));
        };
        ready_commit(inner.begin_dispatch()).map_err(DispatchFailure::known)?;
        inner.confirm_dispatch();
        Ok(())
    }

    pub fn actual(&self, output: &DriverOutput) -> Charge {
        self.billing.actual(output)
    }

    pub fn settle(
        mut self,
        charge: Charge,
        output: DriverOutput,
    ) -> (DriverOutput, Result<(), Failure>) {
        let Some(mut inner) = self.inner.take() else {
            return (output, Err(owner_unavailable()));
        };
        let result = ready_commit(inner.begin_settlement(charge, &output));
        if result.is_ok() {
            inner.confirm_settlement();
        }
        (output, result)
    }
}

fn ready_commit(commit: Ready<Result<(), Failure>>) -> Result<(), Failure> {
    commit.into_inner()
}

fn owner_unavailable() -> Failure {
    Failure::policy("accounting", "reservation owner is no longer available")
}

struct ProcessPermit {
    processes: ProcessTable,
    process: ProcessId,
}

impl ProcessPermit {
    fn apply(&self, settlement: Settlement) {
        self.processes.settle(
            self.process,
            settlement.reserved.micro_usd,
            settlement.actual.micro_usd,
            settlement.reserved.tokens,
            settlement.actual.tokens,
        );
    }
}

impl AccountPermit for ProcessPermit {
    type Error = Failure;
    type Commit = Ready<Result<(), Failure>>;

    fn dispatch(&mut self) -> Self::Commit {
        ready(Ok(()))
    }

    fn settle(&mut self, completion: AccountCompletion<'_>) -> Self::Commit {
        self.apply(completion.settlement());
        ready(Ok(()))
    }

    fn abandon(&mut self, settlement: Settlement) {
        self.apply(settlement);
    }
}
