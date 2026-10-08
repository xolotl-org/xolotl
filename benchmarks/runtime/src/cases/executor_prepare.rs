//! A warmed hosted admission path, with no Driver call in the samples.

use super::{Config, Work};
use anyhow::{Context, ensure};
use std::sync::Arc;
use xolotl_graph::OperationTemplate;
use xolotl_kernel::{Bootstrap, DynDriver, EchoDriver, Executor, KernelBuilder, MethodSpec};
use xolotl_types::{MethodAuthority, OutputMode, Purity};

pub struct ExecutorPrepareCase {
    // Keep the root's owner alive through the measured calls.
    boot: Bootstrap,
    executor: Executor,
    template: OperationTemplate,
    width: usize,
    expected_handles: usize,
}

impl ExecutorPrepareCase {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let boot = Bootstrap::from_kernel(
            KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend()).build(),
        );
        let driver: DynDriver = Arc::new(EchoDriver);
        let methods = [MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )];
        let mut templates = Vec::with_capacity(config.width.get());
        for index in 0..config.width.get() {
            let path = format!("effect://runtime-bench/prepare/{index}");
            let target = boot
                .register_effect(&path, &methods, driver.clone())
                .with_context(|| format!("registering preparation resource {index}"))?;
            templates.push(OperationTemplate {
                target,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            });
        }

        let executor = boot.kernel().executor_for(boot.root());
        // Populate both the method and handle caches after all registrations.
        // The measured samples use the same Executor and one of these templates.
        for (index, template) in templates.iter().enumerate() {
            executor
                .prepare_operation(template)
                .with_context(|| format!("warming preparation resource {index}"))?;
        }
        let template = templates.swap_remove(0);
        let expected_handles = boot.kernel().handles().len();
        ensure!(
            expected_handles == config.width.get(),
            "preparation did not install one handle per resource"
        );
        Ok(Self {
            boot,
            executor,
            template,
            width: config.width.get(),
            expected_handles,
        })
    }

    pub fn run(&self, config: &Config) -> anyhow::Result<Work> {
        ensure!(config.width.get() == self.width, "fixture width changed");
        let template = std::hint::black_box(&self.template);
        for _ in 0..config.work.get() {
            self.executor
                .prepare_operation(template)
                .context("warmed operation preparation failed")?;
        }
        ensure!(
            self.boot.kernel().handles().len() == self.expected_handles,
            "warmed preparation changed the handle count"
        );
        Ok(Work {
            units: config.work.get() as u64,
            unit: "warmed Executor::prepare_operation with a cached valid handle",
        })
    }
}
