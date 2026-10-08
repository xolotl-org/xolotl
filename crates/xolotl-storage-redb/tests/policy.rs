use anyhow::ensure;
use std::sync::Arc;
use xolotl_kernel::policy::{CheckCtx, PolicyDecision, PolicySnapshot, RateLimitCheck};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{Failure, IdentityRef, ResourceId, Value};

fn policies(store: &RedbStore) -> Result<PolicySnapshot, Failure> {
    let backend = store.state_backend().into_backend();
    Ok(PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(
        "effect://models/infer",
        1,
        1000,
        backend,
    )?)]))
}

#[tokio::test]
async fn shared_rate_account_survives_database_reopen() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policies.redb");
    {
        let store = RedbStore::open(&path)?;
        let snapshot = policies(&store)?;
        ensure!(
            snapshot
                .check(&CheckCtx {
                    input: &Value::null(),
                    acting: IdentityRef::ROOT,
                    now_millis: 10,
                    target: ResourceId::new(7),
                })
                .await
                .is_allow()
        );
    }
    let store = RedbStore::open(&path)?;
    let snapshot = policies(&store)?;
    let input = Value::null();
    let mut ctx = CheckCtx {
        input: &input,
        acting: IdentityRef::ROOT,
        now_millis: 20,
        target: ResourceId::new(99),
    };
    ensure!(matches!(
        snapshot.check(&ctx).await,
        PolicyDecision::Deny { .. }
    ));
    ctx.now_millis = 1010;
    ensure!(snapshot.check(&ctx).await.is_allow());
    Ok(())
}
