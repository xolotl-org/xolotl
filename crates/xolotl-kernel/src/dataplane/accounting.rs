//! Reservation ownership for the hosted invocation boundary.

use crate::invocation::{AccountPermit, Billing, Charge, Settlement};
use crate::process::ProcessTable;
use xolotl_types::{DriverOutput, MethodContract, Operation, ProcessId};

pub(super) struct Reservation<'a> {
    billing: Billing,
    inner: crate::invocation::Reservation<ProcessPermit<'a>>,
}

impl<'a> Reservation<'a> {
    pub fn reserve(
        processes: &'a ProcessTable,
        op: &Operation,
        contract: MethodContract,
    ) -> Result<Self, String> {
        let billing = Billing::new(&op.input, contract);
        let charge = billing.reservation();
        processes.reserve(op.process, charge.micro_usd, charge.tokens)?;
        Ok(Self {
            billing,
            inner: crate::invocation::Reservation::new(
                ProcessPermit {
                    processes,
                    process: op.process,
                },
                charge,
            ),
        })
    }

    pub fn dispatched(&mut self) {
        self.inner.dispatch();
    }

    pub fn actual(&self, output: &DriverOutput) -> Charge {
        self.billing.actual(output)
    }

    pub fn settle(self, charge: Charge) {
        self.inner.complete(charge);
    }
}

struct ProcessPermit<'a> {
    processes: &'a ProcessTable,
    process: ProcessId,
}

impl AccountPermit for ProcessPermit<'_> {
    fn settle(&mut self, settlement: Settlement) {
        self.processes.settle(
            self.process,
            settlement.reserved.micro_usd,
            settlement.actual.micro_usd,
            settlement.reserved.tokens,
            settlement.actual.tokens,
        );
    }
}
