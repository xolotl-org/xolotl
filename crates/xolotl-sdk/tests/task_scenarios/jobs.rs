use super::support::{Running, commit, invoke, lock, objects, read_back, record, request, stream};
use anyhow::{Context, bail, ensure};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::watch;
use xolotl_kernel::host::stream::StreamItem;
use xolotl_kernel::{DriverOutput, MethodSpec};
use xolotl_sdk::{
    Driver, DriverContext, DriverError, ExecutionOutput, OperationId, Outcome, PreparedProgram,
    ProcessId, Purity, TaintSet, TaintedValue, Value, Xolotl,
};
use xolotl_state::object::{ObjectMetadata, ObjectRead};
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{MethodId, OutputMode, Path, TaintSource};

const SUBMIT: &str = "perform://effect/scenario/job/submit";
const OBSERVE: &str = "perform://effect/scenario/job/observe";
const CANCEL: &str = "perform://effect/scenario/job/cancel";

#[derive(Clone, Debug, Eq, PartialEq)]
enum Status {
    Running(u32),
    Completed(ObjectMetadata),
    Cancelled,
}

impl Status {
    fn value(&self, id: OperationId) -> TaintedValue {
        let (state, detail, taint) = match self {
            Self::Running(step) => (
                "running",
                Value::integer(i64::from(*step)),
                TaintSet::pristine(),
            ),
            Self::Completed(artifact) => (
                "completed",
                Value::blob(artifact.blob.clone()),
                artifact.taint.clone(),
            ),
            Self::Cancelled => ("cancelled", Value::null(), TaintSet::pristine()),
        };
        TaintedValue::new(
            record([
                ("job", Value::string(id.to_string())),
                ("state", Value::string(state.into())),
                ("detail", detail),
            ]),
            taint,
        )
    }
}

struct Job {
    owner: ProcessId,
    specification: Value,
    status: watch::Sender<Status>,
}

/// Test external service. Its progress endpoint reports the latest status; it
/// does not promise a durable event history. One status is retained per job.
struct Service {
    objects: FileObjectStore,
    jobs: Mutex<BTreeMap<OperationId, Arc<Job>>>,
    observers: AtomicUsize,
    cancel_calls: AtomicUsize,
}

impl Service {
    fn submit(
        &self,
        id: OperationId,
        owner: ProcessId,
        specification: Value,
    ) -> anyhow::Result<OperationId> {
        let mut jobs = lock(&self.jobs);
        if let Some(job) = jobs.get(&id) {
            ensure!(
                job.owner == owner && job.specification == specification,
                "idempotency key changed its request"
            );
        } else {
            let (status, _receiver) = watch::channel(Status::Running(0));
            jobs.insert(
                id,
                Arc::new(Job {
                    owner,
                    specification,
                    status,
                }),
            );
        }
        Ok(id)
    }

    fn job(&self, id: OperationId, owner: ProcessId) -> anyhow::Result<Arc<Job>> {
        let job = lock(&self.jobs)
            .get(&id)
            .cloned()
            .context("unknown external job")?;
        ensure!(job.owner == owner, "job belongs to another request");
        Ok(job)
    }

    fn progress(&self, id: OperationId, step: u32) -> anyhow::Result<()> {
        let job = lock(&self.jobs)
            .get(&id)
            .cloned()
            .context("unknown external job")?;
        job.status.send_if_modified(|state| {
            if matches!(state, Status::Running(previous) if *previous < step) {
                *state = Status::Running(step);
                true
            } else {
                false
            }
        });
        Ok(())
    }

    async fn complete(&self, id: OperationId, artifact: ObjectMetadata) -> anyhow::Result<bool> {
        // A backend callback can publish only a committed, readable artifact.
        ensure!(self.objects.metadata(&artifact.blob).await?.as_ref() == Some(&artifact));
        let job = lock(&self.jobs)
            .get(&id)
            .cloned()
            .context("unknown external job")?;
        let mut conflict = false;
        let changed = job.status.send_if_modified(|state| match state {
            Status::Running(_) => {
                *state = Status::Completed(artifact.clone());
                true
            }
            Status::Completed(previous) => {
                conflict = *previous != artifact;
                false
            }
            Status::Cancelled => false,
        });
        ensure!(!conflict, "completed job received a conflicting artifact");
        Ok(changed)
    }

    fn cancel(&self, id: OperationId, owner: ProcessId) -> anyhow::Result<Status> {
        let job = self.job(id, owner)?;
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        job.status.send_if_modified(|state| {
            if matches!(state, Status::Running(_)) {
                *state = Status::Cancelled;
                true
            } else {
                false
            }
        });
        let result = job.status.borrow().clone();
        Ok(result)
    }
}

struct Observation(Arc<Service>);

impl Drop for Observation {
    fn drop(&mut self) {
        // Local subscription release is synchronous. Remote cancellation is a
        // separate admitted operation and cannot be run by this destructor.
        self.0.observers.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Action {
    Submit,
    Observe,
    Cancel,
}

struct JobDriver {
    service: Arc<Service>,
    action: Action,
}

#[async_trait]
impl Driver for JobDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let failure = |error: anyhow::Error| DriverError::Other(error.to_string());
        if matches!(self.action, Action::Submit) {
            let operation = context
                .operation_id
                .ok_or_else(|| DriverError::Other("missing operation identity".into()))?;
            let id = self
                .service
                .submit(operation, context.caller, input)
                .map_err(failure)?;
            return Ok(DriverOutput::new(Outcome::Done(Value::string(
                id.to_string(),
            ))));
        }
        let id = input
            .as_str()
            .and_then(|text| text.parse::<OperationId>().ok())
            .ok_or_else(|| {
                DriverError::InvalidInput("job identity must be an OperationId".into())
            })?;
        if matches!(self.action, Action::Cancel) {
            let status = self
                .service
                .cancel(id, context.caller)
                .map_err(failure)?
                .value(id);
            return Ok(DriverOutput::new(Outcome::Done(status.value)).with_taint(status.taint));
        }
        let job = self.service.job(id, context.caller).map_err(failure)?;
        self.service.observers.fetch_add(1, Ordering::SeqCst);
        let _observation = Observation(self.service.clone());
        let mut subscription = job.status.subscribe();
        loop {
            let status = subscription.borrow_and_update().clone();
            let terminal = !matches!(status, Status::Running(_));
            let event = status.value(id);
            context.emit_tainted(event.clone()).await?;
            if terminal {
                return Ok(DriverOutput::new(Outcome::Done(event.value)).with_taint(event.taint));
            }
            subscription
                .changed()
                .await
                .map_err(|error| DriverError::Other(error.to_string()))?;
        }
    }
}

struct Programs {
    submit: PreparedProgram,
    observe: PreparedProgram,
    cancel: PreparedProgram,
}

fn install(runtime: &Xolotl) -> anyhow::Result<(tempfile::TempDir, Arc<Service>, Programs)> {
    let (directory, objects) = objects()?;
    let service = Arc::new(Service {
        objects,
        jobs: Mutex::new(BTreeMap::new()),
        observers: AtomicUsize::new(0),
        cancel_calls: AtomicUsize::new(0),
    });
    let submit = runtime.bootstrap().register_effect(
        "effect://scenario/job/submit",
        &[MethodSpec::unary_async("invoke", Purity::Idempotent)],
        Arc::new(JobDriver {
            service: service.clone(),
            action: Action::Submit,
        }),
    )?;
    let observe = runtime.bootstrap().register_effect(
        "effect://scenario/job/observe",
        &[MethodSpec::stream_async("invoke", Purity::Pure).observes_external()],
        Arc::new(JobDriver {
            service: service.clone(),
            action: Action::Observe,
        }),
    )?;
    let cancel = runtime.bootstrap().register_effect(
        "effect://scenario/job/cancel",
        &[MethodSpec::unary_async("invoke", Purity::Idempotent).finalize_allowed()],
        Arc::new(JobDriver {
            service: service.clone(),
            action: Action::Cancel,
        }),
    )?;
    Ok((
        directory,
        service,
        Programs {
            submit: invoke(submit, OutputMode::Unary)?,
            observe: invoke(observe, OutputMode::Stream)?,
            cancel: invoke(cancel, OutputMode::Unary)?,
        },
    ))
}

fn done(output: ExecutionOutput) -> anyhow::Result<TaintedValue> {
    output
        .into_result()
        .map_err(|error| anyhow::anyhow!("job operation failed: {error:?}"))
}

async fn event(
    running: &mut Running<'_>,
    receiver: &mut xolotl_kernel::host::stream::StreamReceiver,
) -> anyhow::Result<TaintedValue> {
    match running.next(receiver).await? {
        StreamItem::Chunk(chunk) => Ok(chunk.into_value()),
        StreamItem::End(end) => bail!("expected progress, received terminal {end:?}"),
    }
}

#[tokio::test]
async fn external_job_publishes_a_committed_artifact_once() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let runtime = Xolotl::new();
        let (_directory, service, programs) = install(&runtime)?;
        let request = request(runtime.bootstrap(), &[SUBMIT, OBSERVE, CANCEL])?;
        let executor = request.executor();
        let specification = Value::string("evaluate model checkpoint".into());
        let submitted = done(
            executor
                .eval_prepared(
                    &programs.submit,
                    TaintedValue::pristine(specification.clone()),
                )
                .await,
        )?;
        let id = submitted
            .value
            .as_str()
            .context("missing job identity")?
            .parse::<OperationId>()?;
        ensure!(id.process == request.id());
        // A duplicated transport submission reuses the actual originating id;
        // a new SDK evaluation would intentionally allocate a different id.
        ensure!(service.submit(id, request.id(), specification)? == id);
        ensure!(lock(&service.jobs).len() == 1);
        ensure!(service.submit(id, request.id(), Value::null()).is_err());

        let (route, mut receiver) = stream();
        let observer = request.executor().with_stream_router(route);
        let mut running =
            Running::new(observer.eval_prepared(&programs.observe, submitted.clone()));
        ensure!(event(&mut running, &mut receiver).await? == Status::Running(0).value(id));
        for step in 1..=32 {
            service.progress(id, step)?;
            ensure!(event(&mut running, &mut receiver).await? == Status::Running(step).value(id));
        }
        let source = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://datasets/training")?,
        });
        let artifact = commit(&service.objects, 32768, 93, &source).await?;
        ensure!(service.complete(id, artifact.clone()).await?);
        ensure!(
            !service.complete(id, artifact.clone()).await?,
            "duplicate callback republished completion"
        );
        let completed = Status::Completed(artifact.clone()).value(id);
        ensure!(event(&mut running, &mut receiver).await? == completed);
        read_back(&service.objects, &artifact, 93).await?;
        let StreamItem::End(end) = running.next(&mut receiver).await? else {
            bail!("duplicate completion produced another artifact event");
        };
        ensure!(end.outcome.is_ok() && end.taint == source);
        ensure!(done(running.finish().await)? == completed);
        ensure!(service.observers.load(Ordering::SeqCst) == 0);
        for _ in 0..2 {
            let cancellation = done(
                executor
                    .eval_prepared(&programs.cancel, submitted.clone())
                    .await,
            )?;
            ensure!(
                cancellation == completed,
                "late cancellation changed a completed artifact"
            );
        }
        ensure!(service.objects.pending_uploads() == 0);
        request
            .finish(&ExecutionOutput::new(
                Outcome::Done(completed.value),
                completed.taint,
            ))
            .await?;
        anyhow::Ok(())
    })
    .await
    .context("job completion scenario timed out")?
}

#[tokio::test]
async fn dropping_observation_requires_explicit_remote_cancellation() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let runtime = Xolotl::new();
        let (_directory, service, programs) = install(&runtime)?;
        let request = request(runtime.bootstrap(), &[SUBMIT, OBSERVE, CANCEL])?;
        let executor = request.executor();
        let submitted = done(
            executor
                .eval_prepared(
                    &programs.submit,
                    TaintedValue::pristine(Value::string("train adapter".into())),
                )
                .await,
        )?;
        let id = submitted
            .value
            .as_str()
            .context("missing job identity")?
            .parse::<OperationId>()?;
        let (route, mut receiver) = stream();
        let observer = request.executor().with_stream_router(route);
        let mut running =
            Running::new(observer.eval_prepared(&programs.observe, submitted.clone()));
        ensure!(event(&mut running, &mut receiver).await? == Status::Running(0).value(id));
        ensure!(service.observers.load(Ordering::SeqCst) == 1);
        drop(running);
        ensure!(service.observers.load(Ordering::SeqCst) == 0);
        ensure!(service.cancel_calls.load(Ordering::SeqCst) == 0);
        ensure!(*service.job(id, request.id())?.status.borrow() == Status::Running(0));

        let other = super::support::request(runtime.bootstrap(), &[CANCEL])?;
        let denied = other
            .executor()
            .eval_prepared(&programs.cancel, submitted.clone())
            .await;
        ensure!(matches!(denied.outcome, Outcome::Fail(_)));
        ensure!(service.cancel_calls.load(Ordering::SeqCst) == 0);
        other.finish(&denied).await?;

        // This explicit, awaited call can also be placed in a graph Finally
        // when the executor is driven to completion. Dropping its future cannot
        // run asynchronous Finally code or confirm remote job cancellation.
        for _ in 0..2 {
            let cancelled = done(
                executor
                    .eval_prepared(&programs.cancel, submitted.clone())
                    .await,
            )?;
            ensure!(cancelled == Status::Cancelled.value(id));
        }
        ensure!(service.cancel_calls.load(Ordering::SeqCst) == 2);
        let artifact = commit(&service.objects, 2048, 42, &TaintSet::pristine()).await?;
        ensure!(
            !service.complete(id, artifact).await?,
            "late completion resurrected a cancelled job"
        );
        let (route, mut receiver) = stream();
        let observer = request.executor().with_stream_router(route);
        let mut running = Running::new(observer.eval_prepared(&programs.observe, submitted));
        ensure!(event(&mut running, &mut receiver).await? == Status::Cancelled.value(id));
        let StreamItem::End(end) = running.next(&mut receiver).await? else {
            bail!("cancelled job retained a live progress subscription");
        };
        ensure!(end.outcome.is_ok());
        let output = running.finish().await;
        ensure!(service.observers.load(Ordering::SeqCst) == 0);
        request.finish(&output).await?;
        anyhow::Ok(())
    })
    .await
    .context("job cancellation scenario timed out")?
}
