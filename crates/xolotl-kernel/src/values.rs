//! Value and provenance semantics shared by portable and hosted execution.

use alloc::{format, vec};
use xolotl_core::Values;
use xolotl_types::{Failure, TaintedFailure, TaintedValue, Value};

/// The standard value algebra for the allocation-free control machine.
/// Control snapshots retain provenance without cloning the input payload.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeValues;

impl Values for RuntimeValues {
    type Value = TaintedValue;
    type Error = TaintedFailure;

    fn unit(&mut self) -> TaintedValue {
        TaintedValue::pristine(Value::null())
    }

    fn truth(&mut self, value: &TaintedValue) -> Result<bool, TaintedFailure> {
        match value.value.as_bool() {
            Some(value) => Ok(value),
            None => Err(TaintedFailure::new(
                Failure::InvalidInput {
                    reason: "condition must produce a boolean".into(),
                },
                value.taint.clone(),
            )),
        }
    }

    fn pair(
        &mut self,
        left: TaintedValue,
        right: TaintedValue,
    ) -> Result<TaintedValue, TaintedFailure> {
        let mut taint = left.taint;
        taint.union(&right.taint);
        Ok(TaintedValue::new(
            Value::list(vec![left.value, right.value]),
            taint,
        ))
    }

    fn error(&mut self, fault: xolotl_core::Fault) -> TaintedFailure {
        TaintedFailure::pristine(match fault {
            xolotl_core::Fault::Cancelled => Failure::Cancelled,
            other => Failure::policy("executor", format!("{other:?}")),
        })
    }

    fn error_value(&mut self, error: TaintedFailure) -> TaintedValue {
        error.into_value()
    }

    fn influence(&mut self, mut value: TaintedValue, control: &TaintedValue) -> TaintedValue {
        value.taint.union(&control.taint);
        value
    }

    fn influence_result(
        &mut self,
        result: Result<TaintedValue, TaintedFailure>,
        control: &TaintedValue,
    ) -> Result<TaintedValue, TaintedFailure> {
        match result {
            Ok(value) => Ok(self.influence(value, control)),
            Err(mut error) => {
                error.taint.union(&control.taint);
                Err(error)
            }
        }
    }

    fn retain_result(&mut self, result: &Result<TaintedValue, TaintedFailure>) -> TaintedValue {
        match result {
            Ok(value) => self.retain_control(value),
            Err(error) => TaintedValue::new(Value::null(), error.taint.clone()),
        }
    }

    fn retain_control(&mut self, input: &TaintedValue) -> TaintedValue {
        TaintedValue::new(Value::null(), input.taint.clone())
    }
}
