use super::*;
use crate::runtime::executions::{ChildRegistration, ExecutionOrigin, ExecutionRegistry};
use xolotl_types::{CausalPosition, ExecutionId, InvocationId, Operation, OperationId};

struct Source {
    registry: Arc<ExecutionRegistry>,
    owner: ExecutionOwner,
    authority: Vec<(String, Path)>,
    reference: ExecutionReference,
    origin: ExecutionOrigin,
    parent: Registration,
    deadline: i64,
}

impl Source {
    async fn new(config: ConsoleExecutionConfig) -> anyhow::Result<Self> {
        let fixture = Fixture::new(config.clone()).await?;
        let registry = ExecutionRegistry::new(config)?;
        let owner = fixture.owner().await?;
        let authority = vec![
            ("perform".into(), Path::parse("effect://jobs/child")?),
            ("spawn-with".into(), Path::parse("effect://jobs/child")?),
        ];
        let deadline = xolotl_kernel::host::system_now_millis() + 60_000;
        let (parent, _, reference) = registry.register(
            owner.clone(),
            authority.clone(),
            ExecutionReference {
                execution_id: None,
                process_id: "7".into(),
                program_id: "source-program".into(),
            },
            deadline,
            xolotl_types::BudgetSpec::default(),
        )?;
        let origin = ExecutionOrigin {
            execution_id: reference.execution_id.clone().context("parent ID")?,
            operation: OperationId::new(
                ProcessId::new(7),
                ExecutionId::new(u64::MAX).context("execution")?,
                InvocationId::new(u64::MAX),
                CausalPosition::new(u32::MAX),
                u32::MAX,
            ),
        };
        Ok(Self {
            registry,
            owner,
            authority,
            reference,
            origin,
            parent,
            deadline,
        })
    }

    fn candidate(&self) -> ExecutionReference {
        ExecutionReference {
            execution_id: None,
            process_id: "8".into(),
            program_id: self.reference.program_id.clone(),
        }
    }

    fn register(&self) -> Result<ChildRegistration, ConsoleError> {
        self.registry.register_child(
            self.owner.clone(),
            self.authority.clone(),
            self.candidate(),
            self.deadline + 1_000,
            self.origin.clone(),
        )
    }
}

#[tokio::test]
async fn reservation_is_not_acceptance_and_rejection_allows_a_fresh_reservation()
-> anyhow::Result<()> {
    let source = Source::new(ConsoleExecutionConfig {
        max_concurrent: 2,
        max_concurrent_per_account: 2,
        max_records: 2,
        max_records_per_account: 2,
        ..config()
    })
    .await?;
    let ChildRegistration::Reserved(mut rejected, _, first) = source.register()? else {
        anyhow::bail!("fresh reservation");
    };
    ensure!(matches!(source.register(), Err(ConsoleError::RateLimited)));
    rejected.reject();
    let ChildRegistration::Reserved(accepted, _, second) = source.register()? else {
        anyhow::bail!("rejected slot must be reusable");
    };
    ensure!(first.execution_id != second.execution_id);
    accepted.accepted();
    let ChildRegistration::Existing(receipt) = source.register()? else {
        anyhow::bail!("accepted receipt must reconcile at capacity");
    };
    ensure!(receipt == second);
    let metadata = source
        .registry
        .get(&source.owner, second.execution_id.as_deref().context("ID")?)?;
    ensure!(field(&metadata, "deadline")?.as_int() == Some(source.deadline));
    let operation: OperationId = field(field(&metadata, "source")?, "operation_id")?
        .as_str()
        .context("operation")?
        .parse()?;
    ensure!(
        operation == source.origin.operation,
        "unsigned coordinates must not be truncated"
    );
    Ok(())
}

#[tokio::test]
async fn receipt_lookup_checks_source_owner_process_program_and_complete_authority()
-> anyhow::Result<()> {
    let source = Source::new(config()).await?;
    let ChildRegistration::Reserved(accepted, _, _) = source.register()? else {
        anyhow::bail!("reservation");
    };
    accepted.accepted();
    for field in ["owner", "parent", "process", "program", "authority"] {
        let mut owner = source.owner.clone();
        let mut origin = source.origin.clone();
        let mut reference = source.candidate();
        let mut authority = source.authority.clone();
        match field {
            "owner" => owner.account_id = "another-account".into(),
            "parent" => origin.execution_id = "another-execution".into(),
            "process" => origin.operation.process = ProcessId::new(9),
            "program" => reference.program_id = "another-program".into(),
            "authority" => {
                authority.pop();
            }
            _ => anyhow::bail!("unknown mismatch case {field}"),
        }
        ensure!(
            matches!(
                source.registry.register_child(
                    owner,
                    authority,
                    reference,
                    source.deadline,
                    origin
                ),
                Err(ConsoleError::BadRequest(_))
            ),
            "accepted mismatched {field}"
        );
    }
    for operation in [
        OperationId {
            invocation: InvocationId::new(1),
            ..source.origin.operation
        },
        OperationId {
            attempt: 0,
            ..source.origin.operation
        },
        OperationId {
            execution: ExecutionId::FIRST,
            ..source.origin.operation
        },
    ] {
        let admission = source.registry.register_child(
            source.owner.clone(),
            source.authority.clone(),
            source.candidate(),
            source.deadline,
            ExecutionOrigin {
                operation,
                ..source.origin.clone()
            },
        )?;
        let ChildRegistration::Reserved(mut distinct, _, _) = admission else {
            anyhow::bail!("distinct causal coordinate was coalesced");
        };
        distinct.reject();
    }
    Ok(())
}

#[tokio::test]
async fn simultaneous_sources_reserve_only_one_child() -> anyhow::Result<()> {
    let source = Source::new(config()).await?;
    let results = std::thread::scope(|scope| {
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let source = &source;
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    source.register()
                })
            })
            .collect();
        jobs.into_iter().map(|job| job.join()).collect::<Vec<_>>()
    });
    let mut reserved = Vec::new();
    for result in results {
        match result.map_err(|_payload| anyhow::anyhow!("reservation thread panicked"))? {
            Ok(ChildRegistration::Reserved(registration, _, reference)) => {
                reserved.push((registration, reference))
            }
            Err(ConsoleError::RateLimited) => {}
            _ => anyhow::bail!("unaccepted receipt escaped"),
        }
    }
    ensure!(reserved.len() == 1);
    let (registration, reference) = reserved.pop().context("one reservation")?;
    registration.accepted();
    for _ in 0..8 {
        let ChildRegistration::Existing(receipt) = source.register()? else {
            anyhow::bail!("receipt did not reconcile");
        };
        ensure!(receipt == reference);
    }
    Ok(())
}

#[tokio::test]
async fn finished_child_cannot_be_forgotten_until_source_finishes() -> anyhow::Result<()> {
    let mut source = Source::new(config()).await?;
    let boot = Bootstrap::in_memory();
    for _ in 2..=7 {
        boot.request_under(boot.root(), xolotl_types::IdentityRef::ROOT, &[])?
            .detach();
    }
    let parent_id = ProcessId::new(7);
    source
        .parent
        .bind_cleanup(boot.cleanup_ticket(parent_id)?)?;
    let child_request = boot.request_under(parent_id, xolotl_types::IdentityRef::ROOT, &[])?;
    let ChildRegistration::Reserved(mut child, _, reference) = source.register()? else {
        anyhow::bail!("reservation");
    };
    child.bind_cleanup(child_request.cleanup_ticket())?;
    child.record_body(Completion {
        outcome: "done".into(),
        stop_cause: None,
        result: RetainedResult::encode(&Value::null(), 1024),
        unresolved_operations: Default::default(),
        cleanup_complete: false,
        finalization: Default::default(),
    });
    let output = ExecutionOutput::new(Outcome::Done(Value::null()), TaintSet::pristine());
    child_request.finish(&output).await?;
    child.settle(true);
    let id = reference.execution_id.as_deref().context("ID")?;
    ensure!(matches!(
        source.registry.forget(&source.owner, id).await,
        Err(ConsoleError::BadRequest(_))
    ));
    ensure!(matches!(source.register()?, ChildRegistration::Existing(_)));
    boot.finish_request_process(parent_id, &output).await?;
    source.parent.settle(true);
    source.registry.forget(&source.owner, id).await?;
    ensure!(source.registry.get(&source.owner, id).is_err());
    ensure!(
        source.register().is_err(),
        "finished sources cannot create another child"
    );
    Ok(())
}

#[tokio::test]
async fn expired_result_keeps_acceptance_until_live_source_releases_it() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    ));
    let f = Fixture::with_boot(
        boot,
        ConsoleExecutionConfig {
            retention_ms: 100,
            max_records: 2,
            max_records_per_account: 2,
            max_concurrent: 2,
            max_concurrent_per_account: 2,
            ..config()
        },
        true,
        true,
    )
    .await?;
    let body = install(&f)?;
    let parent_id = f
        .submit(invoke()?.then(wait()), Value::bytes(vec![0, 255]))
        .await?;
    entered(&body).await?;
    let list = f
        .call(ACTION_RUNTIME_EXECUTION_LIST, Value::null())
        .await?
        .output
        .context("list")?;
    let rows = field(&list, "entries")?.as_list().context("rows")?;
    let child_row = rows
        .iter()
        .find(|row| field(row, "source").is_ok_and(|v| !v.is_null()))
        .context("child")?;
    let id = field(child_row, "execution_id")?
        .as_str()
        .context("child ID")?
        .to_owned();
    let origin = field(child_row, "source")?;
    ensure!(field(origin, "execution_id")?.as_str() == Some(parent_id.as_str()));
    let source_id: OperationId = field(origin, "operation_id")?
        .as_str()
        .context("operation")?
        .parse()?;
    let kernel = f.state.boot.kernel();
    ensure!(kernel.facts().facts_of(source_id.process)?.is_empty());
    let target = Path::parse("effect://jobs/child")?;
    let resource = kernel
        .registry()
        .resolve_resource(&ResourceName::new(target.clone()))?;
    let (method_index, method) = kernel
        .registry()
        .resource_method(resource, "invoke")
        .context("child method")?;
    let acting = kernel
        .processes()
        .identity(source_id.process)
        .context("parent identity")?;
    let handle = xolotl_kernel::prepare_open(
        kernel.registry(),
        xolotl_kernel::OpenRequest {
            process: source_id.process,
            resource,
            verb: "perform".into(),
            rights: xolotl_types::Rights::new(
                xolotl_types::MethodBitmap::method(method_index),
                xolotl_types::RightFlags::SPAWN_WITH,
            ),
            acting,
            requested_path: Some(target),
            now_millis: xolotl_kernel::host::system_now_millis(),
        },
        &kernel.processes().attached_grants(source_id.process),
    )?
    .install(kernel.handles())?;
    let operation = Operation {
        id: source_id,
        process: source_id.process,
        acting,
        handle,
        method: method.id,
        input: Value::bytes(vec![0, 255]),
        taint: TaintSet::author(),
        output: OutputMode::AsyncProcess,
    };
    let parent = f
        .call(ACTION_RUNTIME_EXECUTION_GET, id_input(&parent_id))
        .await?
        .output
        .context("parent")?;
    ensure!(field(&parent, "source")?.is_null());
    let parent_reference: ExecutionReference =
        serde_json::from_value(serde_json::to_value(field(&parent, "execution")?)?)?;
    ensure!(parent_reference.process_id == source_id.process.get().to_string());
    let host = crate::service::runtime::executions::children::Host::new(
        &f.state,
        f.owner().await?,
        vec![
            ("perform".into(), Path::parse("effect://jobs/child")?),
            ("spawn-with".into(), Path::parse("effect://jobs/child")?),
        ],
        vec![
            xolotl_types::Capability::parse("perform://effect/jobs/child")?,
            xolotl_types::Capability::parse("spawn-with://effect/jobs/child")?,
        ],
        parent_reference,
        f.state
            .boot
            .kernel()
            .host_runtime()
            .deadline_after(Duration::from_secs(5))
            .context("deadline")?,
    );
    let dp = f
        .state
        .boot
        .kernel()
        .data_plane()
        .with_async_process_host(Arc::new(host));
    let options = xolotl_kernel::InvocationOptions {
        caller_identity: None,
        now_millis: xolotl_kernel::host::system_now_millis(),
        record: false,
    };
    let replayed = dp.execute(&operation, options).await;
    ensure!(replayed.completion_error.is_none());
    ensure!(replayed.output.outcome == Outcome::Done(field(child_row, "execution")?.clone()));
    let children = f
        .state
        .boot
        .kernel()
        .processes()
        .children_of(source_id.process);
    body.release.notify_one();
    f.finished(&id).await?;
    tokio::time::sleep(Duration::from_millis(120)).await;
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id))
            .await
            .is_err()
    );
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
            .await
            .is_err()
    );
    let replayed_after_expiry = dp.execute(&operation, options).await;
    ensure!(replayed_after_expiry.completion_error.is_none());
    ensure!(replayed_after_expiry.output.outcome == replayed.output.outcome);
    ensure!(
        f.state
            .boot
            .kernel()
            .processes()
            .children_of(source_id.process)
            == children
    );
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    let list = f
        .call(ACTION_RUNTIME_EXECUTION_LIST, Value::null())
        .await?
        .output
        .context("list")?;
    ensure!(
        field(&list, "entries")?
            .as_list()
            .context("visible rows")?
            .len()
            == 1
    );
    ensure!(
        f.submit(echo()?, Value::null()).await.is_err(),
        "pinned receipt must still consume quota"
    );
    f.call(ACTION_RUNTIME_EXECUTION_CANCEL, id_input(&parent_id))
        .await?;
    f.finished(&parent_id).await?;
    let next = f.submit(echo()?, Value::null()).await?;
    ensure!(field(&f.finished(&next).await?, "outcome")?.as_str() == Some("done"));
    Ok(())
}
