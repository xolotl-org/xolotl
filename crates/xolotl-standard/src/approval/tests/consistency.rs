use super::*;
use std::sync::{Arc, Mutex};
use xolotl_state::{StateMutation, StateWrite};
use xolotl_types::{TaintSet, TaintSource};

#[tokio::test]
async fn missing_check_and_response_preserve_absence_evidence() -> Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let path = ApprovalDriver::key_path("deleted")?;
    let sources = TaintSet::of(TaintSource::Protected { path: path.clone() });
    state
        .write_set_tainted(&path, Value::null(), sources.clone())
        .await?;
    state.write_delete(&path).await?;
    let driver = ApprovalDriver::new(state, HostRuntime::default());
    let checked = driver
        .call(MethodId::new(1), ask("deleted"), OutputMode::Unary, &ctx())
        .await?;
    ensure!(checked.outcome == Outcome::Done(Value::null()) && checked.taint == sources);
    let mut input = ask("deleted").into_map().context("approval input")?;
    input.insert("approver".into(), Value::string("alice".into()))?;
    input.insert("decision".into(), Value::string("approve".into()))?;
    let response = driver
        .call(
            MethodId::new(2),
            Value::from(input),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(matches!(response.outcome, Outcome::Fail(_)) && response.taint == sources);
    Ok(())
}

struct ManualClock(std::sync::atomic::AtomicI64);

impl ManualClock {
    fn at(now: i64) -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicI64::new(now)))
    }

    fn set(&self, now: i64) {
        self.0.store(now, std::sync::atomic::Ordering::SeqCst);
    }

    fn runtime(self: &Arc<Self>) -> xolotl_kernel::host::HostRuntime {
        struct Tasks(xolotl_kernel::host::HostRuntime);

        impl xolotl_kernel::host::TaskSpawner for Tasks {
            fn spawn(
                &self,
                future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
            ) -> std::result::Result<
                Arc<dyn xolotl_kernel::host::AbortTask>,
                xolotl_kernel::host::TaskSpawnError,
            > {
                self.0.spawn(future)
            }
        }

        xolotl_kernel::host::HostRuntime::new(
            self.clone(),
            Arc::new(Tasks(xolotl_kernel::host::HostRuntime::tokio())),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        )
    }
}

impl xolotl_kernel::host::HostClock for ManualClock {
    fn monotonic_now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }

    fn unix_millis(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn sleep_until(
        &self,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep_until(deadline.into()))
    }
}

enum ConcurrentChange {
    Respond {
        decision: &'static str,
        advance_to: Option<i64>,
    },
    Delete,
}

struct BeforeCommit {
    state: Backend,
    path: Path,
    change: Mutex<Option<ConcurrentChange>>,
    clock: Arc<ManualClock>,
}

impl StateWrite for BeforeCommit {
    type Write<'a> = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = xolotl_state::StateResult<xolotl_state::StateCommit>>
                + Send
                + 'a,
        >,
    >;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let change = if path == &self.path {
                self.change
                    .lock()
                    .map_err(|_error| {
                        xolotl_state::StateError::Backend("change lock poisoned".into())
                    })?
                    .take()
            } else {
                None
            };
            match change {
                Some(ConcurrentChange::Respond {
                    decision,
                    advance_to,
                }) => {
                    self.clock.set(500);
                    let driver = ApprovalDriver::new(self.state.clone(), self.clock.runtime());
                    let key = path.segments().last().ok_or_else(|| {
                        xolotl_state::StateError::Backend("missing approval key".into())
                    })?;
                    let input = Value::map(BTreeMap::from([
                        ("dedup_key".into(), Value::string(key.to_string())),
                        ("approver".into(), Value::string("bob".into())),
                        ("decision".into(), Value::string(decision.into())),
                    ]));
                    let output = driver
                        .call(
                            MethodId::new(2),
                            input,
                            OutputMode::Unary,
                            &ctx().with_taint(TaintSet::of(TaintSource::Fetched {
                                host: "broker.example".into(),
                            })),
                        )
                        .await
                        .map_err(|error| xolotl_state::StateError::Backend(error.to_string()))?;
                    assert!(matches!(output.outcome, Outcome::Done(_)));
                    if let Some(now) = advance_to {
                        self.clock.set(now);
                    }
                }
                Some(ConcurrentChange::Delete) => {
                    self.state.write_delete(path).await?;
                }
                None => {}
            }
            self.state.mutate(path, mutation).await
        })
    }
}

#[tokio::test]
async fn responses_merge_votes_preserve_terminal_decisions_and_do_not_resurrect() -> Result<()> {
    let mut failures = Vec::new();
    for (case, fanout, slow, concurrent, expected) in [
        ("all", "require_all", "approve", Some("approve"), "approved"),
        ("approved", "any_one", "deny", Some("approve"), "approved"),
        ("denied", "any_one", "approve", Some("deny"), "denied"),
        ("deleted", "any_one", "approve", None, "missing"),
        (
            "stale_expiry",
            "any_one",
            "approve",
            Some("approve"),
            "approved",
        ),
        (
            "deadline",
            "require_all",
            "approve",
            Some("approve"),
            "expired",
        ),
    ] {
        let state = InMemoryBackend::new().into_backend();
        let clock = ManualClock::at(if case == "stale_expiry" { 1_001 } else { 500 });
        let driver = ApprovalDriver::new(state.clone(), clock.runtime());
        let input = Value::map(BTreeMap::from([
            ("dedup_key".into(), Value::string(case.into())),
            ("fanout".into(), Value::string(fanout.into())),
            (
                "approvers".into(),
                str_list(&["alice".into(), "bob".into()]),
            ),
            ("deadline_millis".into(), Value::integer(1_000)),
        ]));
        driver
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await?;
        let path = ApprovalDriver::key_path(case)?;
        let mut events = state.subscribe(&path).await?;
        let gate = Arc::new(BeforeCommit {
            state: state.clone(),
            path: path.clone(),
            change: Mutex::new(Some(concurrent.map_or(
                ConcurrentChange::Delete,
                |decision| ConcurrentChange::Respond {
                    decision,
                    advance_to: matches!(case, "deadline" | "stale_expiry").then_some(1_001),
                },
            ))),
            clock: clock.clone(),
        });
        let checked = ApprovalDriver::new(state.clone().with_write(gate.clone()), clock.runtime());
        let input = Value::map(BTreeMap::from([
            ("dedup_key".into(), Value::string(case.into())),
            ("approver".into(), Value::string("alice".into())),
            ("decision".into(), Value::string(slow.into())),
        ]));
        let incoming = TaintSet::of(TaintSource::ModelOutput);
        let result = checked
            .call(
                MethodId::new(2),
                input,
                OutputMode::Unary,
                &ctx().with_taint(incoming.clone()),
            )
            .await?;
        ensure!(
            gate.change
                .lock()
                .map_err(|_error| anyhow::anyhow!("change lock poisoned"))?
                .is_none(),
            "{case} boundary not reached"
        );
        let current = state.read(&path).await?;
        let valid = if expected == "missing" {
            matches!(&result.outcome, Outcome::Fail(xolotl_types::Failure::Custom { kind, message }) if kind == "approval" && message.contains("record missing"))
                && current.is_none()
        } else {
            let record = Record::from_value(current.as_ref().context("current record")?)?;
            ensure!(
                result.taint
                    == incoming.merged(&TaintSet::of(TaintSource::Fetched {
                        host: "broker.example".into()
                    })),
                "{case} lost response sources"
            );
            result.outcome == Outcome::Done(Value::string(expected.into()))
                && record.status == expected
                && (case != "all" || record.approvals.len() == 2)
        };
        if !valid {
            failures.push(case);
        }
        let mut commits = 0;
        while events.try_recv().is_ok() {
            commits += 1;
        }
        ensure!(
            commits
                == if matches!(case, "all" | "deadline") {
                    2
                } else {
                    1
                },
            "{case} rewrote a terminal or missing record"
        );
    }
    ensure!(
        failures.is_empty(),
        "incorrect competing response: {failures:?}"
    );
    Ok(())
}

struct AdvanceAfterRead {
    state: Backend,
    path: Path,
    clock: Arc<ManualClock>,
    armed: std::sync::atomic::AtomicBool,
}

impl xolotl_state::StateRead for AdvanceAfterRead {
    type Read<'a> = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = xolotl_state::StateResult<xolotl_state::StateObservation>,
                > + Send
                + 'a,
        >,
    >;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            let observed = self.state.read_tainted(path).await?;
            if path == &self.path && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.clock.set(1_001);
            }
            Ok(observed)
        })
    }
}

enum WriteFault {
    Conflict,
    NoCommit,
    LostAck,
}

struct FaultingWrites {
    state: Backend,
    fault: WriteFault,
    calls: std::sync::atomic::AtomicUsize,
}

impl StateWrite for FaultingWrites {
    type Write<'a> = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = xolotl_state::StateResult<xolotl_state::StateCommit>>
                + Send
                + 'a,
        >,
    >;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            assert!(matches!(
                &mutation,
                StateMutation::CompareSet {
                    expected: Some(_),
                    ..
                }
            ));
            let attempt = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let extra = TaintSet::of(TaintSource::Fetched {
                host: format!("attempt-{attempt}.example").into(),
            });
            match self.fault {
                WriteFault::Conflict => {
                    let current = self.state.read(path).await?.ok_or_else(|| {
                        xolotl_state::StateError::Backend("pending record missing".into())
                    })?;
                    let mut fields = current
                        .as_map()
                        .ok_or_else(|| {
                            xolotl_state::StateError::Backend("record fields missing".into())
                        })?
                        .iter()
                        .map(|(key, value)| (key.to_owned(), value.clone()))
                        .collect::<BTreeMap<_, _>>();
                    fields.insert(
                        "revision".into(),
                        Value::integer(i64::try_from(attempt).map_err(|error| {
                            xolotl_state::StateError::Backend(error.to_string())
                        })?),
                    );
                    self.state
                        .write_set_tainted(path, Value::map(fields), extra)
                        .await?;
                    self.state.mutate(path, mutation).await
                }
                WriteFault::NoCommit => Err(xolotl_state::StateFailure::from(
                    xolotl_state::StateError::Backend("approval write refused".into()),
                )
                .with_taint(&extra)),
                WriteFault::LostAck => {
                    let committed = self.state.mutate(path, mutation).await?;
                    Err(xolotl_state::StateFailure::from(
                        xolotl_state::StateError::CommitUncertain(
                            "approval acknowledgement lost".into(),
                        ),
                    )
                    .with_taint(&committed.taint)
                    .with_taint(&extra))
                }
            }
        })
    }
}

#[tokio::test]
async fn responses_bound_conflicts_and_never_replay_known_or_unknown_write_failures() -> Result<()>
{
    for (fault, expected_calls, expected_status, expected_kind) in [
        (WriteFault::Conflict, 8, "pending", "approval"),
        (WriteFault::NoCommit, 1, "pending", "approval"),
        (WriteFault::LostAck, 1, "approved", "state_commit_uncertain"),
    ] {
        let state = InMemoryBackend::new().into_backend();
        let original = ApprovalDriver::new(state.clone(), HostRuntime::default());
        original
            .call(MethodId::new(0), ask("bounded"), OutputMode::Unary, &ctx())
            .await?;
        let path = ApprovalDriver::key_path("bounded")?;
        let writes = Arc::new(FaultingWrites {
            state: state.clone(),
            fault,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let checked = ApprovalDriver::new(
            state.clone().with_write(writes.clone()),
            HostRuntime::default(),
        );
        let input = Value::map(BTreeMap::from([
            ("dedup_key".into(), Value::string("bounded".into())),
            ("approver".into(), Value::string("alice".into())),
            ("decision".into(), Value::string("approve".into())),
        ]));
        let input_taint = TaintSet::of(TaintSource::ModelOutput);
        let output = checked
            .call(
                MethodId::new(2),
                input,
                OutputMode::Unary,
                &ctx().with_taint(input_taint.clone()),
            )
            .await?;
        let kind = match &output.outcome {
            Outcome::Fail(
                xolotl_types::Failure::Custom { kind, .. }
                | xolotl_types::Failure::HandlerError { kind, .. },
            ) => kind,
            other => bail!("expected response failure, got {other:?}"),
        };
        ensure!(kind == expected_kind);
        ensure!(writes.calls.load(std::sync::atomic::Ordering::SeqCst) == expected_calls);
        let mut expected_taint = input_taint;
        for attempt in 1..=expected_calls {
            expected_taint.union(&TaintSet::of(TaintSource::Fetched {
                host: format!("attempt-{attempt}.example").into(),
            }));
        }
        ensure!(
            output.taint.contains_all(&expected_taint)
                && expected_taint.contains_all(&output.taint),
            "lost response evidence: {output:?}"
        );
        let current = Record::from_value(&state.read(&path).await?.context("record")?)?;
        ensure!(current.status == expected_status);
    }
    Ok(())
}

#[tokio::test]
async fn installed_approval_uses_host_time_and_readonly_check_cannot_override_it() -> Result<()> {
    use xolotl_graph::{DoNode, OperationTemplate};
    use xolotl_kernel::{Bootstrap, KernelBuilder};
    use xolotl_types::ResourceName;

    let clock = ManualClock::at(500);
    let state = InMemoryBackend::new().into_backend();
    let delayed_read = Arc::new(AdvanceAfterRead {
        state: state.clone(),
        path: ApprovalDriver::key_path("timed")?,
        clock: clock.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
    });
    let boot = Bootstrap::from_kernel(
        KernelBuilder::new(state.clone().with_read(delayed_read.clone()))
            .with_host_runtime(clock.runtime())
            .build(),
    );
    crate::install_standard(
        &boot,
        &crate::StandardConfig::default()
            .with_modules(crate::StandardModules::none().with(crate::StandardModule::Approval)),
    )?;
    let execute = async |effect: &str, input: Value| -> Result<Outcome> {
        let name = ResourceName::new(Path::parse(effect)?);
        let handle = boot.open_for(boot.root(), &name, "perform")?;
        let executor = boot.kernel().executor_for(boot.root());
        executor.bind_handle(name.clone(), handle)?;
        Ok(executor
            .eval(&DoNode::Op(OperationTemplate {
                target: name,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(input),
            }))
            .await
            .outcome)
    };
    let input = Value::map(BTreeMap::from([
        ("dedup_key".into(), Value::string("timed".into())),
        ("deadline_millis".into(), Value::integer(1_000)),
    ]));
    ensure!(matches!(
        execute("effect://approval/ask", input).await?,
        Outcome::Done(_)
    ));
    let path = ApprovalDriver::key_path("timed")?;
    let original = state.read(&path).await?;
    let mut events = state.subscribe(&path).await?;
    let mut failures = Vec::new();
    for (now, expected) in [(500, "pending"), (1_000, "pending"), (1_001, "expired")] {
        clock.set(now);
        if execute("effect://approval/check", ask("timed")).await?
            != Outcome::Done(Value::string(expected.into()))
        {
            failures.push(now);
        }
    }
    ensure!(state.read(&path).await? == original);
    ensure!(matches!(
        events.try_recv(),
        Err(xolotl_state::StateWatchError::Empty)
    ));
    clock.set(500);
    delayed_read
        .armed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    ensure!(
        execute("effect://approval/check", ask("timed")).await?
            == Outcome::Done(Value::string("expired".into()))
    );
    ensure!(!delayed_read.armed.load(std::sync::atomic::Ordering::SeqCst));
    let override_time = Value::map(BTreeMap::from([
        ("dedup_key".into(), Value::string("timed".into())),
        ("now_millis".into(), Value::integer(0)),
    ]));
    if !matches!(
        execute("effect://approval/check", override_time).await?,
        Outcome::Fail(_)
    ) {
        failures.push(-1);
    }
    let response = Value::map(BTreeMap::from([
        ("dedup_key".into(), Value::string("timed".into())),
        ("approver".into(), Value::string("alice".into())),
        ("decision".into(), Value::string("approve".into())),
    ]));
    if execute("effect://approval/respond", response.clone()).await?
        != Outcome::Done(Value::string("expired".into()))
    {
        failures.push(-2);
    }
    let committed = state.read(&path).await?.context("expired record")?;
    let record = Record::from_value(&committed)?;
    ensure!(record.status == STATUS_EXPIRED && record.approvals.is_empty());
    ensure!(events.try_recv().is_ok(), "missing expiration commit");
    clock.set(500);
    ensure!(
        execute("effect://approval/check", ask("timed")).await?
            == Outcome::Done(Value::string("expired".into()))
    );
    ensure!(
        execute("effect://approval/respond", response).await?
            == Outcome::Done(Value::string("expired".into()))
    );
    ensure!(state.read(&path).await? == Some(committed));
    ensure!(matches!(
        events.try_recv(),
        Err(xolotl_state::StateWatchError::Empty)
    ));
    ensure!(
        failures.is_empty(),
        "incorrect host deadline or override: {failures:?}"
    );
    Ok(())
}
