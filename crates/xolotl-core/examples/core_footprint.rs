//! Reproducible core scalar-machine latency and fixed-storage measurement.
use std::{hint::black_box, io::Write, mem::size_of_val, time::Instant};
use xolotl_core::*;

struct Scalars;
impl Values for Scalars {
    type Value = i64;
    type Error = Fault;
    fn unit(&mut self) -> i64 {
        0
    }
    fn truth(&mut self, value: &i64) -> Result<bool, Fault> {
        Ok(*value != 0)
    }
    fn pair(&mut self, _a: i64, _b: i64) -> Result<i64, Fault> {
        Err(Fault::Type)
    }
    fn error(&mut self, fault: Fault) -> Fault {
        fault
    }
    fn error_value(&mut self, _error: Fault) -> i64 {
        -1
    }
}

fn main() -> anyhow::Result<()> {
    let nodes = [Node::new(NodeKind::Input, 0)];
    let image = ProgramImage {
        version: IMAGE_VERSION,
        id: [0; 32],
        nodes: &nodes,
        entry: 0,
        bindings: 0,
        imports: 0,
        durable: false,
    };
    let mut tasks = [Task::default()];
    let mut frames = [];
    let mut bindings = [];
    let limits = ExecutionLimits {
        frames_per_task: 0,
        bindings_per_task: 0,
        ..ExecutionLimits::default()
    };
    let storage = size_of_val(&tasks) + size_of_val(&frames) + size_of_val(&bindings);
    let mut batches = [0u64; 1000];
    for batch in &mut batches {
        let start = Instant::now();
        for _ in 0..1000 {
            let mut execution = Execution::new(
                black_box(&image),
                &mut tasks,
                &mut frames,
                &mut bindings,
                limits,
                black_box(42),
                1,
            )?;
            match black_box(execution.advance(&image, &mut Scalars, 16)) {
                Advance::Done(Ok(42)) => {}
                result => anyhow::bail!("unexpected result: {result:?}"),
            }
        }
        *batch = u64::try_from(start.elapsed().as_nanos() / 1000)?;
    }
    batches.sort_unstable();
    let execution = Execution::new(&image, &mut tasks, &mut frames, &mut bindings, limits, 0, 1)?;
    writeln!(
        std::io::stdout().lock(),
        "scalar image: {} bytes\nmutable task/frame storage: {storage} bytes\nexecution controller: {} bytes\n1000-operation batch means: p50={} ns/op, p99={} ns/op\nincludes admission and storage reset; excludes I/O and model inference",
        size_of_val(&nodes),
        size_of_val(&execution),
        batches[500],
        batches[990]
    )?;
    Ok(())
}
