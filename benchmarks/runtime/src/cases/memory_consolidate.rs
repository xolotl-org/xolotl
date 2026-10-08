use super::{Config, Work};
use anyhow::{Context, ensure};
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};
use xolotl_kernel::{Bootstrap, KernelBuilder, invocation::InvocationOptions};
use xolotl_standard::{
    EchoBackend, StandardConfig, StandardModule, StandardModules, install_standard,
};
use xolotl_state::{InMemoryBackend, InMemoryOptions, MemoryHistory, StateScan};
use xolotl_types::{
    DriverOutput, HandleId, IdentityRef, InvocationId, MethodId, NodeId, Operation, OperationId,
    Outcome, OutputMode, Path, ResourceName, TaintSet, Value,
};

const RECORD_LIMIT: usize = 256;
const ENCODED_LIMIT: usize = 1024 * 1024;
const TEXT_LIMIT: usize = 64 * 1024;

pub struct MemoryConsolidateCase {
    boot: Bootstrap,
    handle: HandleId,
    input: Value,
    namespace: Path,
    records: BTreeMap<String, String>,
    handles: usize,
}

impl MemoryConsolidateCase {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        ensure!(
            config.width.get() <= RECORD_LIMIT,
            "memory fixture exceeds fixed record limit"
        );
        ensure!(
            config.depth.get() <= 32,
            "memory fixture supports at most 32 words per record"
        );
        let state = InMemoryBackend::with_options(InMemoryOptions {
            history: MemoryHistory::Disabled,
            ..Default::default()
        })?;
        let boot = Bootstrap::from_kernel(KernelBuilder::new(state.into_backend()).build());
        let standard = StandardConfig::default()
            .with_modules(StandardModules::none().with(StandardModule::Memory))
            .with_inference_backend(Arc::new(EchoBackend))
            .with_memory_consolidation_limits(
                NonZeroUsize::MIN.saturating_add(RECORD_LIMIT - 1),
                NonZeroUsize::MIN.saturating_add(ENCODED_LIMIT - 1),
                NonZeroUsize::MIN.saturating_add(TEXT_LIMIT - 1),
            );
        install_standard(&boot, &standard)?;
        let store = ResourceName::new(Path::parse("effect://memory/store")?);
        let store_handle = boot.open_for(boot.root(), &store, "perform")?;
        let mut text_bytes = 0usize;
        let mut records = BTreeMap::new();
        for record in 0..config.width.get() {
            let id = format!("record-{record}");
            let content = (0..config.depth.get())
                .map(|word| format!("r{record}w{word}"))
                .collect::<Vec<_>>()
                .join(" ");
            text_bytes = text_bytes
                .checked_add(content.len())
                .context("fixture text size overflow")?;
            ensure!(
                text_bytes <= TEXT_LIMIT,
                "memory fixture exceeds fixed text limit"
            );
            records.insert(id.clone(), content.clone());
            let input = Value::map(BTreeMap::from([
                ("owner".into(), Value::string("runtime-bench".into())),
                ("namespace".into(), Value::string("consolidate".into())),
                ("id".into(), Value::string(id.clone())),
                ("content".into(), Value::string(content)),
            ]));
            let output = invoke(&boot, store_handle, input).await?;
            let Outcome::Done(value) = &output.outcome else {
                anyhow::bail!("memory fixture seed failed: {:?}", output.outcome);
            };
            ensure!(
                value
                    .as_map()
                    .and_then(|fields| fields.get("id"))
                    .and_then(Value::as_str)
                    == Some(id.as_str()),
                "memory seed returned a different record"
            );
        }
        let resource = ResourceName::new(Path::parse("effect://memory/consolidate")?);
        let handle = boot.open_for(boot.root(), &resource, "perform")?;
        let handles = boot.kernel().handles().len();
        let case = Self {
            boot,
            handle,
            input: Value::map(BTreeMap::from([
                ("owner".into(), Value::string("runtime-bench".into())),
                ("namespace".into(), Value::string("consolidate".into())),
            ])),
            namespace: Path::parse("state://memory/runtime-bench/consolidate")?,
            records,
            handles,
        };
        case.check_namespace().await?;
        case.consolidate().await?;
        case.check_namespace().await?;
        Ok(case)
    }

    pub async fn run(&self, config: &Config) -> anyhow::Result<Work> {
        for _ in 0..config.work.get() {
            self.consolidate().await?;
        }
        self.check_namespace().await?;
        ensure!(
            self.boot.kernel().handles().len() == self.handles,
            "memory calls retained new handles"
        );
        ensure!(
            self.boot.kernel().processes().len() == 1,
            "memory calls retained extra processes"
        );
        Ok(Work {
            units: config.work.get() as u64,
            unit: "public Kernel memory consolidation calls with zero-summary checks, output release and final namespace verification",
        })
    }

    async fn consolidate(&self) -> anyhow::Result<()> {
        let output = invoke(&self.boot, self.handle, self.input.clone()).await?;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(0)),
            "disjoint working records produced summaries or invalid output: {:?}",
            output.outcome
        );
        drop(output);
        Ok(())
    }

    async fn check_namespace(&self) -> anyhow::Result<()> {
        let mut query = StateScan::new(self.namespace.clone());
        let mut count = 0usize;
        loop {
            let page = self.boot.kernel().state().query(&query).await?;
            for (path, entry) in &page.entries {
                let fields = entry.value.as_map().context("memory record is not a map")?;
                let id = fields
                    .get("id")
                    .and_then(Value::as_str)
                    .context("memory record lost its id")?;
                ensure!(
                    path.segments().last().map(|segment| segment.as_str()) == Some(id),
                    "memory record id differs from its storage key"
                );
                let expected = self
                    .records
                    .get(id)
                    .context("memory retained an unexpected record")?;
                ensure!(
                    fields.get("content").and_then(Value::as_str) == Some(expected.as_str()),
                    "memory record content changed, invalidating the disjoint-word workload"
                );
                ensure!(
                    fields.get("tier").and_then(Value::as_str) == Some("working"),
                    "memory tier changed"
                );
                ensure!(
                    fields.get("kind").and_then(Value::as_str) == Some("fact"),
                    "memory retained a summary"
                );
            }
            count = count
                .checked_add(page.entries.len())
                .context("memory record count overflow")?;
            ensure!(
                count <= self.records.len(),
                "memory namespace retained additional records"
            );
            if let Some(cursor) = page.next {
                query.cursor = Some(cursor);
            } else {
                break;
            }
        }
        ensure!(
            count == self.records.len(),
            "memory namespace lost working records"
        );
        Ok(())
    }
}

async fn invoke(boot: &Bootstrap, handle: HandleId, input: Value) -> anyhow::Result<DriverOutput> {
    let process = boot.root();
    let operation = Operation {
        id: OperationId::new(
            process,
            boot.kernel().execution_ids().allocate()?,
            InvocationId::new(1),
            NodeId::new(0),
            0,
        ),
        process,
        acting: IdentityRef::ROOT,
        handle,
        method: MethodId::new(0),
        input,
        taint: TaintSet::pristine(),
        output: OutputMode::Unary,
    };
    let result = boot
        .kernel()
        .data_plane()
        .execute(
            &operation,
            InvocationOptions {
                now_millis: 0,
                caller_identity: Some(IdentityRef::ROOT),
                record: false,
            },
        )
        .await;
    ensure!(
        result.completion_error.is_none(),
        "memory invocation completion failed: {:?}",
        result.completion_error
    );
    Ok(result.output)
}
