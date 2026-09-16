use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn owns_future<F: Future + Send + 'static>(future: F) -> F {
    future
}

fn runtime(fixture: &Fixture) -> anyhow::Result<Arc<GatewayRuntime>> {
    Ok(Arc::new(
        GatewayRuntime::new(
            fixture.boot.clone(),
            echo_profile(xolotl_types::ResourceName::new(Path::parse(
                "effect://echo/say",
            )?))?,
        )?
        .with_object_store(fixture.files.clone().into_object_store()),
    ))
}

#[tokio::test]
async fn object_safe_adapter_opens_workspace_lazily_and_preserves_the_single_owner()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = Arc::new(RecordingPolicy::default());
    let factory_calls = calls.clone();
    let externalizer = runtime(&fixture)?.output_externalizer(
        NonZeroUsize::MIN.saturating_add(100),
        options(),
        move || {
            factory_calls.fetch_add(1, Ordering::AcqRel);
            std::future::ready(Ok::<_, core::convert::Infallible>(keys()))
        },
        policy.clone(),
    );
    ensure!(calls.load(Ordering::Acquire) == 0);
    let original = completion(
        Outcome::Short(Value::from("owned facade")),
        TaintSet::author(),
        CompletionOrigin::CachedOutcome,
    );
    let operation = owns_future(externalizer.externalize(
        fixture.session.clone(),
        original.accepted.clone(),
        GatewayOutputEvent::Complete(original.clone()),
    ));
    ensure!(
        calls.load(Ordering::Acquire) == 0,
        "constructing an unpolled event opened a workspace"
    );
    let output = operation.await?;
    ensure!(calls.load(Ordering::Acquire) == 1);
    ensure!(
        output.kind() == GatewayOutputKind::Short
            && output.origin() == Some(CompletionOrigin::CachedOutcome)
    );
    let GatewayOutputEvent::Complete(retained) = output.original_event() else {
        bail!("facade changed completion role")
    };
    ensure!(retained == &original);
    ensure!(decode(&fixture, &output).await?.value == Value::from("owned facade"));
    ensure!(policy.proposed_expiries.lock().as_slice() == [output.grant().expires_at_ms()]);
    ensure!(fixture.files.pending_uploads() == 0);
    Ok(())
}

#[tokio::test]
async fn workspace_factory_failure_keeps_event_sources_without_disclosing_credentials()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let policy = Arc::new(RecordingPolicy::default());
    let externalizer = runtime(&fixture)?.output_externalizer(
        NonZeroUsize::MIN,
        options(),
        || std::future::ready(Err::<MemoryKeyStore, _>("workspace is unavailable")),
        policy.clone(),
    );
    let source = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://private/original-output")?,
    });
    let original = completion(
        Outcome::Done(Value::integer(8)),
        source.clone(),
        CompletionOrigin::CurrentAttempt,
    );
    let failure = match owns_future(externalizer.externalize(
        fixture.session.clone(),
        original.accepted.clone(),
        GatewayOutputEvent::Complete(original),
    ))
    .await
    {
        Ok(_) => bail!("failed workspace opened an output object"),
        Err(failure) => failure,
    };
    ensure!(failure.taint == source);
    ensure!(!failure.error.to_string().contains(TEST_TOKEN));
    ensure!(failure.error.public_message() == "request rejected");
    ensure!(policy.observed.lock().is_empty());
    ensure!(fixture.files.pending_uploads() == 0 && grant_count(&fixture).await? == 0);
    Ok(())
}
