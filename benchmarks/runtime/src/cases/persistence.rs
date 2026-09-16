use super::{Config, Work, resident};
use anyhow::{Context, ensure};
use xolotl_state::{InMemoryBackend, InMemoryOptions, MemoryHistory, StateRead, StateWriteExt};
use xolotl_types::{
    DecisionTag, ExecutionId, Fact, HandleId, IdentityRef, InvocationId, MethodId, NodeId,
    OperationId, Path, ProcessId, ReplayClass, ResourceId, TaintSet, TaintSource, Timestamp, Value,
};

pub async fn run(config: &Config, path: &Path) -> anyhow::Result<Work> {
    let state = InMemoryBackend::with_options(InMemoryOptions {
        history: MemoryHistory::Disabled,
        ..Default::default()
    })?;
    let value = resident::shared(config.width.get())?;
    let identity = value.identity();
    let sources = TaintSet::of(TaintSource::ModelOutput);
    state
        .write_set_tainted(path, value, sources.clone())
        .await?;
    let read = state.read_tainted(path).await?.context("state value")?;
    ensure!(read.value.identity() == identity && read.taint == sources);
    let input = read.value;
    let fact = Fact {
        id: OperationId::new(
            ProcessId::new(2),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(0),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(2),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        outcome: Some(input.clone()),
        input,
        taint: read.taint,
        decision: DecisionTag::Ok,
        batch: None,
        replay: ReplayClass::Deterministic,
        timestamp: Timestamp::millis(0),
    };
    let encoded = serde_json::to_vec(&fact)?;
    let restored: Fact = serde_json::from_slice(&encoded)?;
    ensure!(restored == fact && restored.taint == sources);
    ensure!(restored.input.identity().is_some());
    ensure!(restored.input.identity() == restored.outcome.as_ref().and_then(Value::identity));
    state
        .write_set_tainted(path, restored.input.clone(), restored.taint.clone())
        .await?;
    let reread = state.read_tainted(path).await?.context("restored state")?;
    ensure!(reread.value.identity() == restored.input.identity() && reread.taint == sources);
    state.write_delete(path).await?;
    ensure!(state.read_tainted(path).await?.is_none());
    drop((reread, restored, encoded, fact, state));
    Ok(Work {
        units: 1,
        unit: "State shared read/write and lossless Fact encode/restore/delete",
    })
}
