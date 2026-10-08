//! An explicitly installed test host, keeping State fault injection out of dispatch.

use super::*;
use crate::host::async_process::{AsyncProcessAdmission, AsyncProcessHost};

pub(crate) type PublishedOutcomes = Arc<parking_lot::Mutex<BTreeMap<ProcessId, ExecutionOutput>>>;

pub(crate) fn state_host(state: Backend) -> Arc<dyn AsyncProcessHost> {
    state_host_with_observer(state, PublishedOutcomes::default())
}

pub(crate) fn state_host_with_observer(
    state: Backend,
    published: PublishedOutcomes,
) -> Arc<dyn AsyncProcessHost> {
    Arc::new(StateHost {
        state,
        prepare_gate: None,
        published,
    })
}

pub(crate) fn state_host_with_prepare_gate(
    state: Backend,
    gate: Arc<PrepareGate>,
    published: PublishedOutcomes,
) -> Arc<dyn AsyncProcessHost> {
    Arc::new(StateHost {
        state,
        prepare_gate: Some(gate),
        published,
    })
}

#[derive(Default)]
pub(crate) struct PrepareGate {
    pub entered: Notify,
    pub release: Notify,
}

struct StateHost {
    state: Backend,
    prepare_gate: Option<Arc<PrepareGate>>,
    published: PublishedOutcomes,
}
struct StateOwner {
    state: Backend,
    prepare_gate: Option<Arc<PrepareGate>>,
    published: PublishedOutcomes,
    request: AsyncProcessRequest,
    process_path: Path,
    status_path: Path,
    outcome_path: Path,
}

fn path_error(error: impl std::fmt::Display) -> Failure {
    Failure::policy("test_async_host", error.to_string())
}

#[async_trait::async_trait]
impl AsyncProcessHost for StateHost {
    async fn admit(&self, request: &AsyncProcessRequest) -> Result<AsyncProcessAdmission, Failure> {
        let suffix = format!(
            "{}/{}",
            request.process.get(),
            request.source.execution.get()
        );
        let owner = Arc::new(StateOwner {
            state: self.state.clone(),
            prepare_gate: self.prepare_gate.clone(),
            published: self.published.clone(),
            request: request.clone(),
            process_path: Path::parse(&format!("proc://async/{suffix}")).map_err(path_error)?,
            status_path: Path::parse(&format!("state://kernel/async/{suffix}/status"))
                .map_err(path_error)?,
            outcome_path: Path::parse(&format!("state://kernel/async/{suffix}/outcome"))
                .map_err(path_error)?,
        });
        let reference = Value::map(BTreeMap::from([
            ("kind".into(), Value::string("executor_resource".into())),
            ("path".into(), Value::string(owner.process_path.to_string())),
            (
                "process".into(),
                Value::integer(request.process.get() as i64),
            ),
            (
                "status_path".into(),
                Value::string(owner.status_path.to_string()),
            ),
            (
                "outcome_path".into(),
                Value::string(owner.outcome_path.to_string()),
            ),
        ]));
        Ok(AsyncProcessAdmission::new(reference, owner))
    }
}

impl StateOwner {
    fn status(&self, status: ProcessStatus, output: Option<&ExecutionOutput>) -> Value {
        let mut fields = BTreeMap::from([
            (
                "phase".into(),
                Value::string(crate::bootstrap::process_status_label(status).into()),
            ),
            ("path".into(), Value::string(self.process_path.to_string())),
            (
                "parent_process".into(),
                Value::integer(self.request.source.process.get() as i64),
            ),
            (
                "process".into(),
                Value::integer(self.request.process.get() as i64),
            ),
            (
                "outcome_path".into(),
                Value::string(self.outcome_path.to_string()),
            ),
        ]);
        if let Some(output) = output {
            fields.insert("outcome".into(), outcome_to_value(&output.outcome));
        }
        Value::map(fields)
    }
}

#[async_trait::async_trait]
impl AsyncProcessOwner for StateOwner {
    async fn prepare(&self) -> Result<(), TaintedFailure> {
        if let Some(gate) = &self.prepare_gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        self.state
            .write_cas_tainted(
                &self.status_path,
                None,
                self.status(ProcessStatus::Running, None),
                self.request.input_taint.clone(),
            )
            .await
            .map(|_commit| ())
            .map_err(|error| {
                TaintedFailure::new(
                    Failure::policy(
                        "async-process",
                        format!("initial status write failed: {error}"),
                    ),
                    error.taint,
                )
            })
    }

    async fn publish(
        &self,
        status: ProcessStatus,
        output: Option<&ExecutionOutput>,
    ) -> Result<(), Failure> {
        let taint = output.map_or_else(
            || self.request.input_taint.clone(),
            |output| output.taint.clone(),
        );
        self.state
            .write_set_tainted(
                &self.outcome_path,
                output.map_or(Value::null(), |output| outcome_to_value(&output.outcome)),
                taint.clone(),
            )
            .await
            .map_err(path_error)?;
        self.state
            .write_set_tainted(&self.status_path, self.status(status, output), taint)
            .await
            .map_err(path_error)?;
        if let Some(output) = output {
            self.published
                .lock()
                .insert(self.request.process, output.clone());
        }
        Ok(())
    }
}
