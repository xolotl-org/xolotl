use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RevokingAuthorizer(AtomicUsize);

#[async_trait::async_trait]
impl RequestAuthorizer for RevokingAuthorizer {
    async fn authorize(&self) -> Result<(), Failure> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(Failure::policy("request", "ownership revoked"))
        }
    }
}

fn options() -> InvocationOptions {
    InvocationOptions {
        now_millis: 0,
        caller_identity: None,
        record: false,
    }
}

#[tokio::test]
async fn cached_results_require_current_request_authority() -> anyhow::Result<()> {
    let (plane, handle) = dataplane_with_handle(
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        FastPath::Unconditional,
        MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY),
    )?;
    let authorizer = Arc::new(RevokingAuthorizer(AtomicUsize::new(0)));
    let plane = plane.with_request_authorizer(authorizer.clone());
    let mut operation = op(
        handle,
        7,
        Value::map(BTreeMap::from([(
            "_idem_key".into(),
            Value::string("same-request".into()),
        )])),
    );
    ensure!(
        plane
            .execute(&operation, options())
            .await
            .output
            .outcome
            .is_success()
    );
    operation.id = operation.id.retry().context("retry exhausted")?;
    let rejected = plane.execute(&operation, options()).await;
    ensure!(
        matches!(rejected.output.outcome, Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "request")
    );
    ensure!(!rejected.effect_may_have_started);
    ensure!(authorizer.0.load(Ordering::SeqCst) == 2);
    ensure!(plane.facts.all_facts()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn asynchronous_children_inherit_request_authority() -> anyhow::Result<()> {
    let (plane, handle, state, facts, processes) =
        async_dataplane(Rights::new(MethodBitmap::method(0), RightFlags::SPAWN_WITH))?;
    let authorizer = Arc::new(RevokingAuthorizer(AtomicUsize::new(0)));
    let plane = plane.with_request_authorizer(authorizer.clone());
    let mut operation = op(handle, 7, Value::string("work".into()));
    operation.output = OutputMode::AsyncProcess;
    let admitted = plane.execute(&operation, options()).await;
    let Outcome::Done(reference) = admitted.output.outcome else {
        bail!("child was not admitted");
    };
    let outcome_path = Path::parse(
        reference
            .as_map()
            .and_then(|map| map.get("outcome_path"))
            .and_then(Value::as_str)
            .context("missing outcome path")?,
    )?;
    let child = ProcessId::new(2);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while processes.status(child) != Some(xolotl_types::ProcessStatus::Failed) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(outcome) = state.read(&outcome_path).await? {
                return Ok::<_, xolotl_state::StateFailure>(outcome);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(
        outcome
            .as_map()
            .and_then(|map| map.get("status"))
            .and_then(Value::as_str)
            == Some("fail")
    );
    ensure!(authorizer.0.load(Ordering::SeqCst) == 2);
    ensure!(facts.is_empty());
    Ok(())
}

struct PendingAuthorizer(tokio::sync::Notify);

#[async_trait::async_trait]
impl RequestAuthorizer for PendingAuthorizer {
    async fn authorize(&self) -> Result<(), Failure> {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn request_authorization_wait_is_bounded_and_releases_reservations() -> anyhow::Result<()> {
    for expired in [false, true] {
        let (plane, handle) = dataplane_with_handle(
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            FastPath::Unconditional,
            MethodContract::new(0, ReplayClass::NonIdempotentEffect, SUPPORTS_UNARY),
        )?;
        let processes = crate::ProcessTable::new();
        let process = ProcessId::new(1);
        let mut entry = crate::process::ProcessEntry::new(process, None, IdentityRef::ROOT);
        ensure!(entry.scope.start());
        processes.insert(entry);
        let authorizer = Arc::new(PendingAuthorizer(tokio::sync::Notify::new()));
        let mut plane = plane
            .with_host_runtime(processes.host_runtime().clone())?
            .with_processes(processes.clone())?
            .with_request_authorizer(authorizer.clone());
        if expired {
            let deadline = processes
                .host_runtime()
                .deadline_after(std::time::Duration::from_secs(5))
                .context("deadline overflow")?;
            plane = plane.with_deadline(deadline)?;
        }
        let operation = op(handle, 7, Value::null());
        let call = plane.execute(&operation, options());
        tokio::pin!(call);
        tokio::select! {
            output = &mut call => bail!("authorization completed before interruption: {output:?}"),
            () = authorizer.0.notified() => {}
        }
        if expired {
            tokio::time::advance(std::time::Duration::from_secs(5)).await;
        } else {
            ensure!(processes.cancel_if_non_terminal(process) == Some(true));
        }
        let output = tokio::time::timeout(std::time::Duration::from_secs(1), call).await?;
        ensure!(
            output.output.outcome
                == Outcome::Fail(if expired {
                    Failure::Timeout
                } else {
                    Failure::Cancelled
                })
        );
        ensure!(!output.effect_may_have_started);
        ensure!(processes.budget_mut(process, |budget| budget.inflight_ops) == Some(0));
        ensure!(plane.facts.all_facts()?.is_empty());
    }
    Ok(())
}
