use super::*;
use anyhow::{Context, ensure};
use xolotl_state::InMemoryBackend;
use xolotl_types::ResourceId;

fn context(input: &Value, now_millis: i64) -> CheckCtx<'_> {
    CheckCtx {
        input,
        acting: IdentityRef::ROOT,
        now_millis,
        target: ResourceId::new(1),
    }
}

#[tokio::test]
async fn changing_the_window_or_reading_corruption_preserves_the_existing_evidence()
-> anyhow::Result<()> {
    let backend = InMemoryBackend::new().into_backend();
    let first = RateLimitCheck::new("uploads", 2, 1000, backend.clone())?;
    let changed = RateLimitCheck::new("uploads", 2, 2000, backend.clone())?;
    let input = Value::null();
    ensure!(first.evaluate(&context(&input, 10)).await.is_allow());
    let path = rate_limit_path("uploads", IdentityRef::ROOT)?;
    let retained = backend.read(&path).await?;
    ensure!(matches!(
        changed.evaluate(&context(&input, 20)).await,
        PolicyDecision::Deny { .. }
    ));
    ensure!(backend.read(&path).await? == retained);
    for malformed in [
        Value::null(),
        Value::list(vec![Value::integer(10)]),
        Value::map(std::collections::BTreeMap::from([
            ("version".into(), Value::integer(1)),
            ("window_millis".into(), Value::integer(1000)),
            ("hits".into(), Value::list(vec![Value::from("bad")])),
        ])),
    ] {
        backend.write_set(&path, malformed.clone()).await?;
        ensure!(matches!(
            first.evaluate(&context(&input, 20)).await,
            PolicyDecision::Deny { .. }
        ));
        ensure!(backend.read(&path).await? == Some(malformed));
    }
    Ok(())
}

#[tokio::test]
async fn timestamp_extremes_and_backward_clocks_do_not_refill_an_active_window()
-> anyhow::Result<()> {
    let backend = InMemoryBackend::new().into_backend();
    let check = RateLimitCheck::new("clock", 1, i64::MAX, backend)?;
    let input = Value::null();
    ensure!(check.evaluate(&context(&input, i64::MIN)).await.is_allow());
    ensure!(matches!(
        check.evaluate(&context(&input, i64::MIN + 1)).await,
        PolicyDecision::Deny { .. }
    ));
    ensure!(check.evaluate(&context(&input, i64::MAX)).await.is_allow());
    ensure!(matches!(
        check.evaluate(&context(&input, 0)).await,
        PolicyDecision::Deny { .. }
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_instances_share_one_atomic_admission_budget() -> anyhow::Result<()> {
    let backend = InMemoryBackend::new().into_backend();
    let allowed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..24 {
        let check = RateLimitCheck::new("concurrent", 3, 1000, backend.clone())?;
        let allowed = allowed.clone();
        tasks.spawn(async move {
            if check.evaluate(&context(&Value::null(), 0)).await.is_allow() {
                allowed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        result?;
    }
    ensure!(allowed.load(std::sync::atomic::Ordering::SeqCst) == 3);
    let stored = backend
        .read(&rate_limit_path("concurrent", IdentityRef::ROOT)?)
        .await?
        .context("stored window")?;
    ensure!(
        decode_rate_hits(Some(&stored), 1000)
            .map_err(anyhow::Error::msg)?
            .len()
            == 3
    );
    Ok(())
}

#[tokio::test]
async fn scopes_are_unambiguous_and_invalid_configuration_is_not_silently_normalized()
-> anyhow::Result<()> {
    let backend = InMemoryBackend::new().into_backend();
    for (scope, window) in [("", 1), (" ", 1), ("valid", 0), ("valid", -1)] {
        ensure!(RateLimitCheck::new(scope, 1, window, backend.clone()).is_err());
    }
    ensure!(RateLimitCheck::new("a".repeat(513), 1, 1000, backend.clone()).is_err());
    ensure!(
        rate_limit_path("a/b", IdentityRef::ROOT)? != rate_limit_path("a%2Fb", IdentityRef::ROOT)?
    );
    ensure!(
        rate_limit_path("a/b", IdentityRef::new(1))?
            != rate_limit_path("a/b", IdentityRef::new(2))?
    );
    let closed = RateLimitCheck::new("closed", 0, 1, backend)?;
    ensure!(matches!(
        closed.evaluate(&context(&Value::null(), 0)).await,
        PolicyDecision::Deny { .. }
    ));
    Ok(())
}
