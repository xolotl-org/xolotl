use super::*;

fn cache_path(operation: &Operation) -> anyhow::Result<Path> {
    let key = xolotl_types::idempotency::derive_key(
        operation.id,
        operation.acting,
        &operation.input,
        xolotl_types::idempotency::KeyScope {
            resource: ResourceId::new(5),
            target: None,
            method: operation.method,
            output: operation.output,
        },
    );
    Ok(idempotency_path(&key)?)
}

async fn seed_cache(
    plane: &DataPlane,
    operation: &Operation,
    sources: &TaintSet,
    present: bool,
) -> anyhow::Result<()> {
    let path = cache_path(operation)?;
    plane
        .state
        .write_set_tainted(
            &path,
            outcome_to_value(&Outcome::Done(Value::integer(23))),
            sources.clone(),
        )
        .await?;
    if !present {
        plane.state.write_delete(&path).await?;
    }
    let observation = plane.state.read_tainted(&path).await?;
    ensure!(observation.value.is_some() == present && observation.taint == *sources);
    Ok(())
}

#[tokio::test]
async fn cache_absence_controls_driver_chunks_results_and_selected_facts() -> anyhow::Result<()> {
    for record in [false, true] {
        let mut fixture = fixture(
            ReplayClass::IdempotentEffect,
            CompletionOrigin::CurrentAttempt,
        )?;
        let (sink, facts) = FactSink::in_memory();
        fixture.plane.facts = sink;
        let mut operation = op(fixture.handle, 7, Value::null());
        operation.output = OutputMode::Stream;
        operation.taint = TaintSet::author();
        let absence = TaintSet::of(TaintSource::ModelOutput);
        seed_cache(&fixture.plane, &operation, &absence, false).await?;
        let control = operation.taint.clone().merged(&absence);
        let expected_output = fixture.output_taint.clone().merged(&control);
        let (sink, mut receiver) = channel(StreamWindow::default());
        let result = fixture
            .plane
            .execute_with_stream(
                &operation,
                InvocationOptions {
                    caller_identity: None,
                    now_millis: 0,
                    record,
                },
                sink,
            )
            .await;
        ensure!(result.output.outcome == Outcome::Done(Value::integer(2)));
        ensure!(result.output.taint == expected_output && result.effect_may_have_started);
        let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
            bail!("driver omitted its chunk");
        };
        ensure!(chunk.taint == expected_output);
        drop(chunk);
        let Some(StreamItem::End(end)) = receiver.recv().await else {
            bail!("driver omitted its terminal");
        };
        ensure!(end.taint == control.clone().merged(&expected_output));
        let retained = facts.facts_of(operation.process)?;
        ensure!(retained.len() == usize::from(record));
        if record {
            ensure!(retained[0].taint == control.merged(&fixture.output_taint));
        }
        ensure!(fixture.calls.load(Ordering::Acquire) == 1);
        ensure!(receiver.recv().await.is_none());
    }
    Ok(())
}

struct DenyDelivery;

#[async_trait::async_trait]
impl RequestAuthorizer for DenyDelivery {
    async fn authorize(&self) -> Result<(), Failure> {
        Err(Failure::policy("request", "revoked"))
    }
}

#[tokio::test]
async fn cache_hit_and_miss_revocation_preserve_the_completed_observation() -> anyhow::Result<()> {
    for present in [false, true] {
        let mut fixture = fixture(
            ReplayClass::IdempotentEffect,
            CompletionOrigin::CurrentAttempt,
        )?;
        fixture.plane = fixture
            .plane
            .with_request_authorizer(Arc::new(DenyDelivery));
        let mut operation = op(fixture.handle, 7, Value::null());
        operation.output = OutputMode::Stream;
        operation.taint = TaintSet::author();
        let observed = TaintSet::of(TaintSource::ModelOutput);
        seed_cache(&fixture.plane, &operation, &observed, present).await?;
        let expected = operation.taint.clone().merged(&observed);
        let (sink, mut receiver) = channel(StreamWindow::default());
        let result = fixture
            .plane
            .execute_with_stream(
                &operation,
                InvocationOptions {
                    caller_identity: None,
                    now_millis: 0,
                    record: true,
                },
                sink,
            )
            .await;
        ensure!(
            matches!(result.output.outcome, Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "request")
        );
        ensure!(result.output.taint == expected && !result.effect_may_have_started);
        ensure!(fixture.calls.load(Ordering::Acquire) == 0);
        ensure!(fixture.plane.facts.facts_of(operation.process)?[0].taint == expected);
        let Some(StreamItem::End(end)) = receiver.recv().await else {
            bail!("revocation omitted its terminal");
        };
        ensure!(end.taint == expected);
    }
    Ok(())
}

#[tokio::test]
async fn protected_cache_absence_rejects_dispatch_but_cached_output_is_not_driver_input()
-> anyhow::Result<()> {
    for present in [false, true] {
        let (plane, handle) = dataplane_with_handle(
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            FastPath::Unconditional,
            MethodContract {
                requires_unprotected_input: true,
                ..MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY)
            },
        )?;
        let operation = op(handle, 7, Value::null());
        let observed = TaintSet::of(TaintSource::Protected {
            path: cache_path(&operation)?,
        });
        seed_cache(&plane, &operation, &observed, present).await?;
        let dispatched = AtomicBool::new(false);
        let result = plane
            .execute_with_dispatch_witness(
                &operation,
                InvocationOptions {
                    caller_identity: None,
                    now_millis: 0,
                    record: false,
                },
                Some(&dispatched),
            )
            .await;
        ensure!(result.output.taint == observed && !dispatched.load(Ordering::Relaxed));
        if present {
            ensure!(result.output.outcome == Outcome::Done(Value::integer(23)));
            ensure!(result.output.origin == CompletionOrigin::CachedOutcome);
        } else {
            ensure!(
                matches!(result.output.outcome, Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "taint")
            );
        }
    }
    Ok(())
}

struct WaitingDelivery(tokio::sync::Notify);

#[async_trait::async_trait]
impl RequestAuthorizer for WaitingDelivery {
    async fn authorize(&self) -> Result<(), Failure> {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn stream_close_and_future_drop_keep_cache_sources_while_authorization_waits()
-> anyhow::Result<()> {
    for close_receiver in [false, true] {
        let mut fixture = fixture(
            ReplayClass::IdempotentEffect,
            CompletionOrigin::CurrentAttempt,
        )?;
        let authorizer = Arc::new(WaitingDelivery(tokio::sync::Notify::new()));
        fixture.plane = fixture.plane.with_request_authorizer(authorizer.clone());
        let mut operation = op(fixture.handle, 7, Value::null());
        operation.output = OutputMode::Stream;
        operation.taint = TaintSet::author();
        let observed = TaintSet::of(TaintSource::ModelOutput);
        seed_cache(&fixture.plane, &operation, &observed, false).await?;
        let expected = operation.taint.clone().merged(&observed);
        let (sink, mut receiver) = channel(StreamWindow::default());
        let mut pending = Box::pin(fixture.plane.execute_with_stream(
            &operation,
            InvocationOptions {
                caller_identity: None,
                now_millis: 0,
                record: false,
            },
            sink,
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::select! {
                result = &mut pending => bail!("authorization ended early: {result:?}"),
                () = authorizer.0.notified() => Ok(()),
            }
        })
        .await??;
        if close_receiver {
            drop(receiver);
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), pending).await?;
            ensure!(result.output.taint == expected && !result.effect_may_have_started);
        } else {
            drop(pending);
            let Some(StreamItem::End(end)) = receiver.recv().await else {
                bail!("future drop omitted its terminal");
            };
            ensure!(end.taint == expected && end.outcome == Err(Failure::Cancelled));
        }
        ensure!(fixture.calls.load(Ordering::Acquire) == 0);
    }
    Ok(())
}
