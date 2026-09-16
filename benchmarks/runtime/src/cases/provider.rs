//! A public admitted HTTP invocation; the complete local host belongs to a sample.

use super::{Config, Work};
use anyhow::{Context, ensure};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use xolotl_kernel::host::stream::{StreamItem, channel};
use xolotl_kernel::stream::StreamWindow;
use xolotl_kernel::{Bootstrap, CompiledRequestGrantTemplate, FactSink, InvocationOptions, Kernel};
use xolotl_standard::{StandardConfig, StandardModule, StandardModules, install_standard};
use xolotl_state::{InMemoryBackend, InMemoryOptions, MemoryHistory};
use xolotl_types::{
    DecisionTag, ExecutionOutput, IdentityRef, InvocationId, MethodBitmap, MethodId, NodeId,
    Operation, OperationId, Outcome, OutputMode, Path, ProcessStatus, ResourceName,
    ResourceSelector, TaintSet, TaintSource, UsageDimension, Value,
};

mod configuration;
mod http;

pub struct ProviderCase {
    listener: std::net::TcpListener,
    declarations: [(Path, Value); 4],
    resource: ResourceName,
    grants: [CompiledRequestGrantTemplate; 1],
    standard: StandardConfig,
}

impl ProviderCase {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let base_url = format!("http://{}/v1", listener.local_addr()?);
        Ok(Self {
            listener,
            declarations: configuration::declarations(&base_url, config.window)?,
            resource: ResourceName::new(Path::parse("effect://inference/infer")?),
            grants: [CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse("perform://effect/inference/infer")?,
                methods: MethodBitmap::method(0),
            }],
            standard: StandardConfig::default()
                .with_modules(StandardModules::none().with(StandardModule::Inference)),
        })
    }

    pub async fn run(&self, config: &Config) -> anyhow::Result<Work> {
        tokio::time::timeout(Duration::from_secs(60), self.run_inner(config))
            .await
            .context("provider-stream local HTTP workload timed out")?
    }

    async fn run_inner(&self, config: &Config) -> anyhow::Result<Work> {
        let state = InMemoryBackend::with_options(InMemoryOptions {
            history: MemoryHistory::Disabled,
            ..Default::default()
        })?
        .into_backend();
        for (path, value) in &self.declarations {
            state.write_set(path, value.clone()).await?;
        }
        let (facts, store) = FactSink::in_memory();
        let weak_facts = Arc::downgrade(&store);
        drop(store);
        let boot = Bootstrap::from_kernel(Kernel::with_backends(state, facts));
        boot.kernel
            .processes
            .set_capacity(Some(NonZeroUsize::MIN.saturating_add(1)))?;
        install_standard(&boot, &self.standard)?;
        let weak_handles = Arc::downgrade(&boot.kernel.handles);
        // The raw listener is a fixture; its registration and accepted socket
        // belong to this sample. No detached server task survives either branch.
        let listener = tokio::net::TcpListener::from_std(self.listener.try_clone()?)?;
        tokio::try_join!(
            http::serve(listener, config.work.get(), config.window.get()),
            self.invoke(&boot, config),
        )?;
        ensure!(boot.kernel.processes.len() == 1 && boot.kernel.handles.read().is_empty());
        drop(boot);
        ensure!(
            weak_handles.upgrade().is_none() && weak_facts.upgrade().is_none(),
            "provider sample retained its host or Fact history"
        );
        drop((weak_handles, weak_facts));
        Ok(Work {
            units: u64::try_from(config.work.get())?,
            unit: "ignored provider snapshot bytes through admitted HTTP/SSE, including host setup and release",
        })
    }

    async fn invoke(&self, boot: &Bootstrap, config: &Config) -> anyhow::Result<()> {
        let request = boot.request_under(boot.root, IdentityRef::ROOT, &self.grants)?;
        let process = request.id();
        let operation = Operation {
            id: OperationId::new(
                process,
                boot.kernel.execution_ids().allocate()?,
                InvocationId::new(1),
                NodeId::new(0),
                0,
            ),
            process,
            acting: IdentityRef::ROOT,
            handle: boot.open_for(process, &self.resource, "perform")?,
            method: MethodId::new(0),
            input: Value::string("prompt".into()),
            taint: TaintSet::pristine(),
            output: OutputMode::Stream,
        };
        let expected_sources = TaintSet::of(TaintSource::ModelOutput);
        let (sink, mut receiver) = channel(StreamWindow {
            max_chunks: NonZeroUsize::MIN,
            max_inline_bytes: config.window,
        });
        let weak_sink = Arc::downgrade(&sink);
        let data_plane = boot.kernel.data_plane();
        let call = async {
            let output = data_plane
                .execute_with_stream(
                    &operation,
                    InvocationOptions {
                        now_millis: 0,
                        record: true,
                    },
                    sink,
                )
                .await;
            ensure!(
                output.outcome == Outcome::Done(Value::null()),
                "provider invocation failed: {:?}",
                output.outcome
            );
            ensure!(output.taint == expected_sources);
            let usage = output.usage.as_ref().context("provider omitted usage")?;
            ensure!(
                usage.len() == 2
                    && usage.get(&UsageDimension::INPUT_TOKENS) == Some(&5)
                    && usage.get(&UsageDimension::OUTPUT_TOKENS) == Some(&7)
            );
            Ok::<_, anyhow::Error>(output)
        };
        let consume = async {
            let mut bytes = 0usize;
            loop {
                match receiver
                    .recv()
                    .await
                    .context("provider stream omitted its terminal")?
                {
                    StreamItem::Chunk(chunk) => {
                        let text = chunk.value.as_str().context("non-text provider chunk")?;
                        ensure!(
                            !text.is_empty()
                                && b"ok".get(bytes..bytes + text.len()) == Some(text.as_bytes()),
                            "provider emitted ignored or unexpected text"
                        );
                        ensure!(chunk.taint == expected_sources);
                        bytes += text.len();
                        drop(chunk);
                    }
                    StreamItem::End(end) => {
                        ensure!(bytes == 2 && end.outcome.is_ok() && end.taint == expected_sources);
                        break;
                    }
                }
            }
            ensure!(receiver.recv().await.is_none());
            Ok::<_, anyhow::Error>(())
        };
        let (output, ()) = tokio::try_join!(call, consume)?;
        drop(receiver);
        ensure!(
            weak_sink.upgrade().is_none(),
            "provider retained its stream owner"
        );
        let fact = boot
            .kernel
            .facts
            .get(operation.id)?
            .context("missing provider Fact")?;
        ensure!(
            fact.decision == DecisionTag::Ok
                && fact.outcome == Some(Value::null())
                && fact.taint == expected_sources
                && fact.caller == process
        );
        let completed = ExecutionOutput::new(output.outcome, output.taint);
        request.finish(&completed).await?;
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Completed));
        ensure!(boot.kernel.processes.reap_finalized(1) == 1);
        drop((data_plane, operation, completed, fact, weak_sink));
        Ok(())
    }
}
