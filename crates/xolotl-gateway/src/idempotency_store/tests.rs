//! Shared acceptance checks for bounded Gateway request stores.

use super::{GatewayIdempotencyRecord, GatewayIdempotencyStore, GatewayIdempotencyUsage};
use crate::GatewayError;
use std::collections::BTreeMap;
use std::sync::Arc;
use xolotl_types::{TaintSet, TaintSource, TaintedValue, Value};

fn base(key: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "schema".into(),
            Value::string("gateway-idempotency-v1".into()),
        ),
        ("effective_key_hash".into(), Value::string(key.into())),
        ("submission_hash".into(), Value::string("b".repeat(64))),
        (
            "caller_material_kind".into(),
            Value::string("idempotency_key".into()),
        ),
        ("caller_material_hash".into(), Value::string("c".repeat(64))),
        ("profile_name".into(), Value::string("acceptance".into())),
        ("profile_rev".into(), Value::string("1".into())),
        ("principal_id".into(), Value::string("alice".into())),
        ("surface_id".into(), Value::string("charge".into())),
    ])
}

fn pending(key: &str) -> TaintedValue {
    let mut fields = base(key);
    fields.insert("state".into(), Value::string("pending".into()));
    fields.insert(
        "reservation_id".into(),
        Value::string(format!("reservation-{key}")),
    );
    fields.insert("created_at_ms".into(), Value::integer(1));
    TaintedValue::new(Value::map(fields), TaintSet::of(TaintSource::ModelOutput))
}

fn completed(key: &str, unknown: bool, incomplete: bool, payload: Value) -> TaintedValue {
    let mut fields = base(key);
    fields.extend([
        ("state".into(), Value::string("committed".into())),
        ("committed_at_ms".into(), Value::integer(2)),
        (
            "accepted_submission_id".into(),
            Value::string(format!("submission-{key}")),
        ),
        (
            "accepted_trace_root".into(),
            Value::string(format!("trace-{key}")),
        ),
        ("accepted_profile_rev".into(), Value::integer(1)),
        ("accepted_surface_id".into(), Value::string("charge".into())),
        ("outcome_status".into(), Value::string("done".into())),
        ("outcome_value".into(), payload),
        (
            "unresolved_operations".into(),
            Value::map(BTreeMap::from([
                (
                    "operation_ids".into(),
                    Value::list(if unknown {
                        vec![Value::string("operation-unknown".into())]
                    } else {
                        Vec::new()
                    }),
                ),
                ("identities_incomplete".into(), Value::boolean(incomplete)),
            ])),
        ),
    ]);
    TaintedValue::new(
        Value::map(fields),
        TaintSet::of(TaintSource::Fetched {
            host: "acceptance-driver".into(),
        }),
    )
}

fn check(condition: bool, message: &str) -> Result<(), GatewayError> {
    if condition {
        Ok(())
    } else {
        Err(GatewayError::Rejected(format!(
            "idempotency acceptance: {message}"
        )))
    }
}

/// Shared backend contract. Supply an empty store with at least three result
/// reservations, four records, and enough per-record capacity for these fixtures.
/// Closed-range uncertain results remain available for adapter reopen checks.
pub async fn gateway_idempotency_acceptance(
    store: Arc<dyn GatewayIdempotencyStore>,
) -> Result<(), GatewayError> {
    let namespace = store.evidence_namespace()?;
    check(
        store.clone().evidence_namespace()? == namespace,
        "shared store changed its evidence namespace",
    )?;
    let limits = store.limits();
    check(
        store.usage().await? == GatewayIdempotencyUsage::default(),
        "store must start empty",
    )?;
    let key = format!("{:064x}", 1);
    let original = pending(&key);
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let key = key.clone();
        let pending = original.clone();
        let barrier = barrier.clone();
        attempts.spawn(async move {
            barrier.wait().await;
            store.reserve(&key, pending).await
        });
    }
    let mut winners = 0;
    while let Some(attempt) = attempts.join_next().await {
        let observed = attempt.map_err(|error| GatewayError::Rejected(error.to_string()))??;
        match observed {
            None => winners += 1,
            Some(observed) => check(
                observed == original,
                "concurrent observer lost pending provenance",
            )?,
        }
    }
    check(
        winners == 1,
        "same-key reserve must have exactly one winner",
    )?;
    let reserved_bytes =
        GatewayIdempotencyRecord::pending(original.clone(), limits)?.charged_bytes();
    check(
        store.usage().await?
            == GatewayIdempotencyUsage {
                records: 1,
                bytes: reserved_bytes,
            },
        "reservation accounting",
    )?;

    let mut reservations = vec![(key.clone(), original.clone())];
    for identity in 2..=limits.max_records.get().saturating_add(1) {
        let next = format!("{identity:064x}");
        let pending = pending(&next);
        match store.reserve(&next, pending.clone()).await {
            Ok(None) => reservations.push((next, pending)),
            Err(GatewayError::LimitExceeded(_)) => break,
            _ => {
                return Err(GatewayError::Rejected(
                    "unexpected capacity reservation result".into(),
                ));
            }
        }
    }
    let full = store.usage().await?;
    check(
        full.records == limits.max_records.get()
            || full
                .bytes
                .checked_add(reserved_bytes)
                .is_none_or(|bytes| bytes > limits.max_bytes.get()),
        "pending capacity was not exhausted",
    )?;
    check(
        store.observe(&key).await? == Some(original.clone()),
        "observe must work at capacity",
    )?;
    check(
        store.reserve(&key, original.clone()).await? == Some(original.clone()),
        "reserve replay must work at capacity",
    )?;
    check(
        store
            .reserve(&key, TaintedValue::pristine(Value::null()))
            .await?
            == Some(original.clone()),
        "existing epoch-zero replay must not require a valid new reservation",
    )?;
    check(
        store.usage().await? == full,
        "capacity replay changed usage",
    )?;
    for (key, pending) in reservations.into_iter().skip(1) {
        store.release(&key, pending.value.clone()).await?;
        check(
            store.release(&key, pending.value).await.is_err(),
            "release succeeded twice",
        )?;
    }

    let before = store.usage().await?;
    let mut wrong = original
        .value
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("acceptance: fixture map missing".into()))?
        .clone();
    wrong
        .insert(
            "reservation_id".into(),
            Value::string("another-owner".into()),
        )
        .map_err(super::decoding_error)?;
    check(
        store
            .release(&key, Value::from(wrong.clone()))
            .await
            .is_err(),
        "foreign reservation released",
    )?;
    check(
        store
            .complete(
                &key,
                Value::from(wrong),
                completed(&key, false, false, Value::null()),
            )
            .await
            .is_err(),
        "foreign reservation settled",
    )?;
    let mut conflict = completed(&key, false, false, Value::null());
    let mut fields = conflict
        .value
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("acceptance: fixture map missing".into()))?
        .clone();
    fields
        .insert("submission_hash".into(), Value::string("d".repeat(64)))
        .map_err(super::decoding_error)?;
    conflict.value = Value::from(fields);
    check(
        store
            .complete(&key, original.value.clone(), conflict)
            .await
            .is_err(),
        "conflicting fingerprint settled",
    )?;
    let oversized = completed(
        &key,
        false,
        false,
        Value::string("x".repeat(limits.max_record_bytes.get())),
    );
    check(
        store
            .complete(&key, original.value.clone(), oversized)
            .await
            .is_err(),
        "oversized result settled",
    )?;
    check(
        store.usage().await? == before && store.observe(&key).await? == Some(original.clone()),
        "failed settlement mutated evidence or accounting",
    )?;
    check(
        store.retire(&key, original.value.clone()).await.is_err(),
        "pending evidence retired",
    )?;
    check(
        store
            .complete(
                &key,
                original.value.clone(),
                in_epoch(completed(&key, false, false, Value::null()), 1)?,
            )
            .await
            .is_err(),
        "settlement changed retry epoch",
    )?;
    check(
        store
            .reserve(&key, in_epoch(original.clone(), 1)?)
            .await
            .is_err(),
        "existing evidence moved to another epoch",
    )?;
    check(
        store.usage().await? == before,
        "epoch binding rejection changed accounting",
    )?;

    let mut result = completed(&key, false, false, Value::string("charged-once".into()));
    result.taint.union(&original.taint);
    store
        .complete(
            &key,
            original.value.clone(),
            completed(&key, false, false, Value::string("charged-once".into())),
        )
        .await?;
    let settled = store.usage().await?;
    check(
        settled
            == GatewayIdempotencyUsage {
                records: 1,
                bytes: GatewayIdempotencyRecord::completed(result.clone(), limits)?.charged_bytes(),
            },
        "settlement did not release unused reservation",
    )?;
    check(
        settled.bytes < before.bytes,
        "fixture must release unused result capacity",
    )?;
    check(
        store.observe(&key).await? == Some(result.clone()),
        "settlement lost result or pending provenance",
    )?;
    check(
        store
            .complete(&key, original.value.clone(), result.clone())
            .await
            .is_err(),
        "settlement succeeded twice",
    )?;
    check(
        store.release(&key, original.value.clone()).await.is_err(),
        "committed evidence released by pending owner",
    )?;
    check(
        store.release(&key, result.value.clone()).await.is_err(),
        "committed evidence released",
    )?;
    check(
        store.usage().await? == settled,
        "repeated settlement or release changed usage",
    )?;

    for (identity, unknown, incomplete) in [(2, true, false), (3, false, true)] {
        let key = format!("{identity:064x}");
        let pending = pending(&key);
        check(
            store.reserve(&key, pending.clone()).await?.is_none(),
            "unknown fixture reserve",
        )?;
        store
            .complete(
                &key,
                pending.value.clone(),
                completed(&key, unknown, incomplete, Value::null()),
            )
            .await?;
        let result = store.observe(&key).await?.ok_or_else(|| {
            GatewayError::Rejected("acceptance: completed fixture missing".into())
        })?;
        let usage = store.usage().await?;
        check(
            store.release(&key, pending.value).await.is_err(),
            "unknown result released",
        )?;
        check(
            store.release(&key, result.value.clone()).await.is_err(),
            "unknown committed evidence released",
        )?;
        check(
            store.retire(&key, result.value.clone()).await.is_err(),
            "unresolved result retired",
        )?;
        check(
            store.usage().await? == usage && store.observe(&key).await? == Some(result),
            "unknown rejection mutated evidence",
        )?;
    }
    let unknown_key = format!("{:064x}", 4);
    let unknown_pending = pending(&unknown_key);
    check(
        store
            .reserve(&unknown_key, unknown_pending.clone())
            .await?
            .is_none(),
        "typed unknown fixture reserve",
    )?;
    let mut unknown_result = completed(&unknown_key, false, false, Value::null());
    let mut fields = unknown_result
        .value
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("acceptance: unknown result map missing".into()))?
        .clone();
    fields.remove("outcome_value");
    fields
        .insert("outcome_status".into(), Value::string("fail".into()))
        .map_err(super::decoding_error)?;
    fields
        .insert(
            "failure_json".into(),
            Value::string(
                serde_json::to_string(&xolotl_types::Failure::OutcomeUnknown {
                    operation_ids: vec!["typed-unknown-operation".into()],
                    reason: "uncertain commit despite incomplete aggregate metadata".into(),
                })
                .map_err(|error| GatewayError::Rejected(error.to_string()))?,
            ),
        )
        .map_err(super::decoding_error)?;
    unknown_result.value = Value::from(fields);
    store
        .complete(&unknown_key, unknown_pending.value, unknown_result)
        .await?;
    let unknown_result = store
        .observe(&unknown_key)
        .await?
        .ok_or_else(|| GatewayError::Rejected("acceptance: typed unknown result missing".into()))?;
    let unknown_usage = store.usage().await?;
    check(
        store
            .retire(&unknown_key, unknown_result.value.clone())
            .await
            .is_err(),
        "typed OutcomeUnknown retired with empty aggregate unresolved evidence",
    )?;
    check(
        store.usage().await? == unknown_usage
            && store.observe(&unknown_key).await? == Some(unknown_result),
        "typed unknown retirement rejection changed evidence or accounting",
    )?;

    let before_retire = store.usage().await?;
    store.retire(&key, result.value.clone()).await?;
    let retired = store
        .observe(&key)
        .await?
        .ok_or_else(|| GatewayError::Rejected("acceptance: retired fixture missing".into()))?;
    let retired_fields = retired
        .value
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("acceptance: fixture map missing".into()))?;
    check(
        retired_fields.get("state").and_then(Value::as_str) == Some("retired"),
        "retirement state",
    )?;
    for (field, value) in base(&key) {
        check(
            retired_fields.get(&field) == Some(&value),
            "retirement lost replay fingerprint",
        )?;
    }
    check(retired.taint == result.taint, "retirement lost provenance")?;
    let after_retire = store.usage().await?;
    check(
        after_retire.records == before_retire.records && after_retire.bytes < before_retire.bytes,
        "retirement must retain record count and release result bytes",
    )?;
    check(
        store.reserve(&key, original.clone()).await? == Some(retired.clone()),
        "retired identity became executable",
    )?;
    check(
        store.retire(&key, result.value).await.is_err(),
        "retirement succeeded twice",
    )?;

    let committed_key = format!("{:064x}", 2);
    let committed = store.observe(&committed_key).await?.ok_or_else(|| {
        GatewayError::Rejected("acceptance: retained unknown result missing".into())
    })?;
    for identity in 5..=limits.max_records.get().saturating_add(1) {
        let next = format!("{identity:064x}");
        let pending = pending(&next);
        match store.reserve(&next, pending.clone()).await {
            Ok(None) => {
                store
                    .complete(
                        &next,
                        pending.value,
                        completed(&next, false, false, Value::null()),
                    )
                    .await?
            }
            Err(GatewayError::LimitExceeded(_)) => break,
            _ => {
                return Err(GatewayError::Rejected(
                    "unexpected completed-capacity result".into(),
                ));
            }
        }
    }
    let full = store.usage().await?;
    let extra_key = format!("{:064x}", limits.max_records.get().saturating_add(2));
    check(
        matches!(
            store.reserve(&extra_key, pending(&extra_key)).await,
            Err(GatewayError::LimitExceeded(_))
        ),
        "completed evidence did not retain capacity",
    )?;
    check(
        store
            .reserve(&committed_key, pending(&committed_key))
            .await?
            == Some(committed),
        "committed replay failed at capacity",
    )?;
    check(
        store.reserve(&key, original).await? == Some(retired),
        "retired replay failed at capacity",
    )?;
    check(
        store.usage().await? == full && store.limits() == limits,
        "replay changed capacity or limits",
    )?;
    check(store.retry_epoch().await? == 0, "initial retry epoch")?;
    check(store.close_retry_epoch(0).await? == 1, "explicit closure")?;
    let after_close = store.usage().await?;
    check(
        after_close.records == 3,
        "closure did not reclaim only certain evidence",
    )?;
    check(
        store.observe(&key).await?.is_none(),
        "closed retired detail retained",
    )?;
    check(
        matches!(
            store.reserve(&key, pending(&key)).await,
            Err(GatewayError::Rejected(_))
        ),
        "closed identity executable after reclamation",
    )?;
    check(
        store.close_retry_epoch(0).await.is_err(),
        "stale closure succeeded",
    )?;
    check(
        store.usage().await? == after_close && store.retry_epoch().await? == 1,
        "stale closure mutated state",
    )?;
    for identity in 2..=4 {
        let retained_key = format!("{identity:064x}");
        let retained = store
            .observe(&retained_key)
            .await?
            .ok_or_else(|| GatewayError::Rejected("missing unresolved closed evidence".into()))?;
        check(
            store.reserve(&retained_key, pending(&retained_key)).await? == Some(retained),
            "closed unresolved replay unavailable",
        )?;
    }
    let live_key = format!("{:064x}", 10000);
    let live = in_epoch(pending(&live_key), 1)?;
    check(
        store.reserve(&live_key, live.clone()).await?.is_none(),
        "new epoch capacity unavailable",
    )?;
    let charged = store.usage().await?;
    check(
        store.close_retry_epoch(1).await? == 2,
        "closure with pending",
    )?;
    check(
        store.usage().await? == charged,
        "closure evicted pending or unknown",
    )?;
    check(
        store.reserve(&live_key, live.clone()).await? == Some(live.clone()),
        "closed pending replay unavailable",
    )?;
    store
        .complete(
            &live_key,
            live.value,
            in_epoch(completed(&live_key, false, false, Value::null()), 1)?,
        )
        .await?;
    check(
        store.close_retry_epoch(2).await? == 3,
        "closed owner could not settle",
    )?;
    check(
        store.observe(&live_key).await?.is_none(),
        "later closure did not reclaim settled owner",
    )?;
    for epoch in 3..35 {
        let rotated_key = format!("{:064x}", 10000 + epoch);
        let next = in_epoch(pending(&rotated_key), epoch)?;
        check(
            store.reserve(&rotated_key, next.clone()).await?.is_none(),
            "long-term rotation exhausted capacity",
        )?;
        store
            .complete(
                &rotated_key,
                next.value,
                in_epoch(completed(&rotated_key, false, false, Value::null()), epoch)?,
            )
            .await?;
        check(
            store.close_retry_epoch(epoch).await? == epoch + 1,
            "monotonic epoch rotation",
        )?;
        check(
            store.usage().await? == after_close,
            "rotation leaked capacity or lost unknown evidence",
        )?;
        check(
            matches!(
                store
                    .reserve(&rotated_key, in_epoch(pending(&rotated_key), epoch)?)
                    .await,
                Err(GatewayError::Rejected(_))
            ),
            "old rotation executable",
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn memory_namespace_is_shared_under_racing_initialization_and_changes_on_replacement()
-> Result<(), GatewayError> {
    let store = Arc::new(super::MemoryGatewayIdempotencyStore::default());
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.evidence_namespace()
            })
        })
        .collect();
    barrier.wait();
    let namespace = store.evidence_namespace()?;
    for worker in workers {
        check(
            worker
                .join()
                .map_err(|_error| GatewayError::Rejected("namespace worker panicked".into()))??
                == namespace,
            "racing readers obtained different ledger identities",
        )?;
    }
    check(
        super::MemoryGatewayIdempotencyStore::default().evidence_namespace()? != namespace,
        "replacement ledger reused the old identity",
    )?;
    check(
        super::GatewayEvidenceNamespace::from_bytes([0; 32]).is_err(),
        "absent identity was accepted",
    )
}

fn in_epoch(mut record: TaintedValue, epoch: u64) -> Result<TaintedValue, GatewayError> {
    let mut fields = record
        .value
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("missing epoch fixture map".into()))?
        .clone();
    fields
        .insert("retry_epoch".into(), Value::string(epoch.to_string()))
        .map_err(super::decoding_error)?;
    record.value = Value::from(fields);
    Ok(record)
}

#[cfg(test)]
#[tokio::test]
async fn memory_accepts_shared_count_and_byte_contracts() -> Result<(), GatewayError> {
    use super::{GatewayIdempotencyLimits, MemoryGatewayIdempotencyStore};
    use std::num::NonZeroUsize;

    for max_bytes in [3 * (4096 + 64), 64 * 1024] {
        let limits = GatewayIdempotencyLimits {
            max_records: NonZeroUsize::new(4)
                .ok_or_else(|| GatewayError::Rejected("acceptance: nonzero missing".into()))?,
            max_bytes: NonZeroUsize::new(max_bytes)
                .ok_or_else(|| GatewayError::Rejected("acceptance: nonzero missing".into()))?,
            max_record_bytes: NonZeroUsize::new(4096)
                .ok_or_else(|| GatewayError::Rejected("acceptance: nonzero missing".into()))?,
        };
        gateway_idempotency_acceptance(Arc::new(MemoryGatewayIdempotencyStore::new(limits)?))
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_closure_is_compare_and_swap_and_never_wraps() -> Result<(), GatewayError> {
    use super::MemoryGatewayIdempotencyStore;

    let store = Arc::new(MemoryGatewayIdempotencyStore::default());
    let mut closers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        closers.spawn(async move { store.close_retry_epoch(0).await });
    }
    let mut winners = 0;
    while let Some(result) = closers.join_next().await {
        match result.map_err(super::decoding_error)? {
            Ok(1) => winners += 1,
            Err(GatewayError::Rejected(_)) => {}
            _ => return Err(GatewayError::Rejected("unexpected closure result".into())),
        }
    }
    check(
        winners == 1 && store.retry_epoch().await? == 1,
        "closure has multiple winners",
    )?;
    store.state.lock().retry_epoch = u64::MAX;
    check(
        store.close_retry_epoch(u64::MAX).await.is_err(),
        "epoch wrapped",
    )?;
    check(
        store.retry_epoch().await? == u64::MAX,
        "overflow reset epoch",
    )?;
    Ok(())
}

#[tokio::test]
async fn default_capacity_recovers_after_4096_unique_protected_results() -> Result<(), GatewayError>
{
    use super::MemoryGatewayIdempotencyStore;

    let store = MemoryGatewayIdempotencyStore::default();
    for epoch in 0..2 {
        for identity in 0..4096 {
            let key = format!("{:064x}", epoch * 4096 + identity);
            let record = in_epoch(pending(&key), epoch)?;
            check(
                store.reserve(&key, record.clone()).await?.is_none(),
                "default unique reservation",
            )?;
            store
                .complete(
                    &key,
                    record.value,
                    in_epoch(completed(&key, false, false, Value::null()), epoch)?,
                )
                .await?;
        }
        check(
            store.usage().await?.records == 4096,
            "default record capacity",
        )?;
        let extra = format!("{:064x}", 100000 + epoch);
        check(
            matches!(
                store
                    .reserve(&extra, in_epoch(pending(&extra), epoch)?)
                    .await,
                Err(GatewayError::LimitExceeded(_))
            ),
            "default capacity not enforced",
        )?;
        check(
            store.close_retry_epoch(epoch).await? == epoch + 1,
            "default closure",
        )?;
        check(
            store.usage().await? == GatewayIdempotencyUsage::default(),
            "default closure retained charges",
        )?;
    }
    Ok(())
}
