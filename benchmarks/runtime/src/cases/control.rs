use super::{Config, Work};
use anyhow::ensure;
use std::hint::black_box;
use xolotl_core::{
    Advance, Execution, ExecutionLimits, Fault, IMAGE_VERSION, Node, NodeKind, ProgramImage, Task,
    Values,
};

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
    fn pair(&mut self, _: i64, _: i64) -> Result<i64, Fault> {
        Err(Fault::Type)
    }
    fn error(&mut self, fault: Fault) -> Fault {
        fault
    }
    fn error_value(&mut self, _: Fault) -> i64 {
        -1
    }
}

pub fn run(config: &Config) -> anyhow::Result<Work> {
    let nodes = [Node {
        next: Some(0),
        ..Node::new(NodeKind::Input, 0)
    }];
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
    let mut machine = Execution::new(
        &image,
        &mut tasks,
        &mut [],
        &mut [],
        ExecutionLimits {
            frames_per_task: 0,
            bindings_per_task: 0,
            max_steps: None,
            cleanup_steps: 64,
            durable: false,
        },
        42,
        1,
    )?;
    let target = u64::try_from(config.work.get())?;
    while machine.checkpoint().meta.steps < target {
        let remaining = target - machine.checkpoint().meta.steps;
        let quantum = u32::try_from(remaining.min(256))?;
        ensure!(matches!(
            black_box(machine.advance(&image, &mut Scalars, quantum)),
            Advance::Yielded
        ));
    }
    ensure!(machine.checkpoint().meta.steps == target);
    machine.cancel();
    ensure!(matches!(
        machine.advance(&image, &mut Scalars, 64),
        Advance::Done(Err(Fault::Cancelled))
    ));
    Ok(Work {
        units: target,
        unit: "ordinary control transitions, then cancellation",
    })
}
