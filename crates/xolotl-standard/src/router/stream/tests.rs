use super::*;
use crate::inference::{InferenceBackend, ModelCapabilities};
use crate::router::{GroupPolicy, ModelEntry, ModelGroup};
use anyhow::{Context, ensure};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use xolotl_kernel::{
    DriverContext,
    host::stream::{StreamItem, channel},
    stream::StreamWindow,
};
use xolotl_types::{IdentityRef, Outcome, ProcessId, TaintSource};

struct Backend {
    calls: AtomicUsize,
    fail: bool,
    emit_before_failure: bool,
}

#[async_trait]
impl InferenceBackend for Backend {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Err("this fixture requires streaming".into())
    }

    async fn embed(&self, _input: &Value) -> Result<Value, String> {
        Err("unsupported".into())
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            streaming: true,
            ..ModelCapabilities::default()
        }
    }

    async fn infer_stream(
        &self,
        _input: &Value,
        stream: &InferenceStream<'_>,
    ) -> Result<DriverOutput, String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            if self.emit_before_failure {
                stream.emit(Value::string("partial".into())).await?;
            }
            Err("503 stream interrupted".into())
        } else {
            stream.emit(Value::string("complete".into())).await?;
            Ok(DriverOutput::new(Outcome::Done(Value::null())))
        }
    }
}

#[tokio::test]
async fn retries_and_fallback_stop_after_first_accepted_chunk() -> anyhow::Result<()> {
    for partial in [false, true] {
        let first = Arc::new(Backend {
            calls: AtomicUsize::new(0),
            fail: true,
            emit_before_failure: partial,
        });
        let fallback = Arc::new(Backend {
            calls: AtomicUsize::new(0),
            fail: false,
            emit_before_failure: false,
        });
        let mut router = Router::new(vec![
            ModelEntry::new("first", first.clone()),
            ModelEntry::new("fallback", fallback.clone()),
        ]);
        router.groups.insert(
            "default".into(),
            ModelGroup::new("default", GroupPolicy::Priority, vec![0]).with_fallback("fallback"),
        );
        router.groups.insert(
            "fallback".into(),
            ModelGroup::new("fallback", GroupPolicy::Priority, vec![1]),
        );
        let (sink, mut receiver) = channel(StreamWindow::default());
        let context =
            DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
        let output = InferenceStream::new(&context);
        let requirements = RequestRequirements {
            needs_streaming: true,
            ..RequestRequirements::default()
        };
        let result = router
            .infer_stream(&Value::null(), &requirements, &output)
            .await;
        ensure!(result.is_err() == partial);
        ensure!(first.calls.load(Ordering::Relaxed) == if partial { 1 } else { 3 });
        ensure!(fallback.calls.load(Ordering::Relaxed) == usize::from(!partial));
        let StreamItem::Chunk(chunk) = receiver.recv().await.context("expected output")? else {
            anyhow::bail!("unexpected terminal")
        };
        ensure!(chunk.value == Value::string(if partial { "partial" } else { "complete" }.into()));
        ensure!(chunk.taint.sources().contains(&TaintSource::ModelOutput));
    }
    Ok(())
}
