use crate::config::Config;

mod bounded;
mod control;
mod executor_prepare;
mod memory_consolidate;
mod objects;
mod persistence;
mod program;
mod provider;
mod resident;
mod streams;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Work {
    pub units: u64,
    pub unit: &'static str,
}

pub enum Case {
    Core,
    SourceFingerprint(bounded::SourceFingerprintCase),
    PlanCompile(bounded::PlanCompileCase),
    MemoryConsolidate(Box<memory_consolidate::MemoryConsolidateCase>),
    Resident,
    ExecutorPrepare(Box<executor_prepare::ExecutorPrepareCase>),
    Program(Box<program::ProgramCase>, bool),
    Stream(bool),
    Provider(Box<provider::ProviderCase>),
    Object(objects::ObjectCase),
    StateFact(xolotl_types::Path),
}

impl Case {
    pub fn new(config: &Config, runtime: &tokio::runtime::Runtime) -> anyhow::Result<Self> {
        Ok(match config.case.as_str() {
            "core" => Self::Core,
            "memory-consolidate" => Self::MemoryConsolidate(Box::new(
                runtime.block_on(memory_consolidate::MemoryConsolidateCase::new(config))?,
            )),
            "source-fingerprint"
            | "source-fingerprint-deep-reject"
            | "source-fingerprint-wide-reject"
            | "source-fingerprint-shared-reject" => {
                Self::SourceFingerprint(bounded::SourceFingerprintCase::new(config)?)
            }
            "plan-compile" | "plan-compile-reject" => {
                Self::PlanCompile(bounded::PlanCompileCase::new(config)?)
            }
            "resident" => Self::Resident,
            "executor-prepare" => Self::ExecutorPrepare(Box::new(
                executor_prepare::ExecutorPrepareCase::new(config)?,
            )),
            "portable" | "hosted" => Self::Program(
                Box::new(program::ProgramCase::new()?),
                config.case == "hosted",
            ),
            "stream" | "stream-cancel" => Self::Stream(config.case == "stream-cancel"),
            "provider-stream" => Self::Provider(Box::new(provider::ProviderCase::new(config)?)),
            "object-file" => Self::Object(objects::ObjectCase::new(config)?),
            "state-fact" => {
                Self::StateFact(xolotl_types::Path::parse("state://runtime-bench/shared")?)
            }
            _ => anyhow::bail!("unknown workload"),
        })
    }

    pub fn run_sample(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        config: &Config,
    ) -> anyhow::Result<Work> {
        // Dispatch before constructing a future. An async enum over every case
        // would charge unrelated large-future boxing to the small workloads.
        match self {
            Self::Core => control::run(config),
            Self::MemoryConsolidate(case) => runtime.block_on(case.run(config)),
            Self::SourceFingerprint(case) => case.run(config),
            Self::PlanCompile(case) => case.run(config),
            Self::Resident => resident::run(config),
            Self::ExecutorPrepare(case) => case.run(config),
            Self::Program(program, true) => runtime.block_on(program.run_hosted(config)),
            Self::Program(program, false) => runtime.block_on(program.run_portable(config)),
            Self::Stream(cancel) => runtime.block_on(streams::run(config, *cancel)),
            Self::Provider(provider) => runtime.block_on(provider.run(config)),
            Self::Object(object) => runtime.block_on(object.run(config)),
            Self::StateFact(path) => runtime.block_on(persistence::run(config, path)),
        }
    }
}
