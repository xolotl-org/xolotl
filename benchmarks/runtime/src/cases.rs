use crate::config::Config;

mod control;
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
    Resident,
    Program(Box<program::ProgramCase>, bool),
    Stream(bool),
    Provider(Box<provider::ProviderCase>),
    Object(objects::ObjectCase),
    StateFact(xolotl_types::Path),
}

impl Case {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        Ok(match config.case.as_str() {
            "core" => Self::Core,
            "resident" => Self::Resident,
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
            Self::Resident => resident::run(config),
            Self::Program(program, true) => runtime.block_on(program.run_hosted(config)),
            Self::Program(program, false) => runtime.block_on(program.run_portable(config)),
            Self::Stream(cancel) => runtime.block_on(streams::run(config, *cancel)),
            Self::Provider(provider) => runtime.block_on(provider.run(config)),
            Self::Object(object) => runtime.block_on(object.run(config)),
            Self::StateFact(path) => runtime.block_on(persistence::run(config, path)),
        }
    }
}
