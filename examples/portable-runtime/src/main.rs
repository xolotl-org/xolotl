use std::io::Write;
use xolotl_portable_example::{run, sample_program};
use xolotl_sdk::types::{TaintedValue, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (output, budget) = run(&sample_program(), TaintedValue::pristine(Value::integer(0)))?;
    writeln!(
        std::io::stdout().lock(),
        "result={:?}, inflight={}, spent={}",
        output,
        budget.inflight_ops,
        budget.spent_micro_usd
    )?;
    Ok(())
}
