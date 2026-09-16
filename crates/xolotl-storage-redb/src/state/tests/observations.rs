use super::*;
use std::num::NonZeroUsize;
use xolotl_types::TaintSource;

fn protected(path: &str) -> anyhow::Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected { path: p(path)? }))
}

fn replace_payload(mut bytes: Vec<u8>, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let length: [u8; 8] = bytes
        .get(4..12)
        .context("missing source prefix")?
        .try_into()?;
    let end = 12usize
        .checked_add(usize::try_from(u64::from_le_bytes(length))?)
        .context("source prefix overflow")?;
    ensure!(end <= bytes.len());
    bytes.truncate(end);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn replace_current(backend: &RedbStateBackend, path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let txn = backend.db.begin_write()?;
    txn.open_table(STATE_VALUES_TABLE)?
        .insert(path.to_string().as_str(), bytes)?;
    txn.commit()?;
    Ok(())
}

#[tokio::test]
async fn failed_atomic_observation_survives_live_deletion() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://observation/atomic")?;
    let taint = protected("state://private/atomic")?;
    let secret = "private-cas-value";
    backend
        .write_set_tainted(&path, Value::string(secret.into()), taint.clone())
        .await?;
    // This backend captures its result in Ready before the consumer polls it.
    let conflict = backend.write_cas_tainted(&path, None, Value::null(), TaintSet::author());
    let append = backend.write_append(&path, Value::null());
    let deletion = backend.write_compare_delete(&path, None);
    backend.write_delete(&path).await?;
    for result in [conflict.await, append.await, deletion.await] {
        let failure = result.err().context("conflicting mutation succeeded")?;
        ensure!(failure.taint.sources().contains(&taint.sources()[0]));
        ensure!(!failure.to_string().contains(secret));
        ensure!(!format!("{failure:?}").contains(secret));
        if let StateError::CasFailed { actual, .. } = failure.error {
            ensure!(actual.as_deref().and_then(Value::as_str) == Some(secret));
        }
    }
    ensure!(backend.read_tainted(&path).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn late_transaction_failure_preserves_current_and_incoming_sources() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://observation/late-commit")?;
    let current = protected("state://private/current")?;
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    let expected = incoming.clone().merged(&current);
    backend
        .write_set_tainted(&path, Value::null(), current.clone())
        .await?;
    set_history_millis(&backend.db, i64::MAX)?;
    let failure = backend
        .write_cas_tainted(&path, Some(Value::null()), Value::integer(2), incoming)
        .await
        .err()
        .context("exhausted transaction succeeded")?;
    ensure!(failure.taint == expected);
    ensure!(
        matches!(failure.error, StateError::Backend(message) if message.contains("timestamp exhausted"))
    );
    ensure!(backend.read_tainted(&path).await? == Some(TaintedValue::new(Value::null(), current)));
    Ok(())
}

#[tokio::test]
async fn deferred_oversized_corrupt_payload_needs_only_its_source_prefix() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let prefix = p("state://observation/page")?;
    let first = prefix.clone().try_push_literal("a")?;
    let second = prefix.clone().try_push_literal("b")?;
    let taint = protected("state://private/oversized")?;
    backend.write_set(&first, Value::null()).await?;
    let malformed = replace_payload(encode_envelope(&Value::null(), &taint)?, &vec![0xff; 4096])?;
    replace_current(&backend, &second, &malformed)?;
    let mut query = xolotl_state::StateScan::new(prefix);
    query.limits.encoded_bytes = NonZeroUsize::new(1024).context("zero page budget")?;
    let page = backend.query(&query).await?;
    ensure!(page.entries.len() == 1 && page.entries[0].0 == first);
    ensure!(page.taint == taint);
    query.cursor = page.next;
    let deferred = backend.query(&query);
    // Deletion also needs no value decoder and still reports observed sources.
    ensure!(backend.write_delete(&second).await?.taint == taint);
    let failure = deferred.await.err().context("oversized row accepted")?;
    ensure!(failure.taint == taint);
    ensure!(matches!(failure.error, StateError::RowTooLarge(row) if row.path == second));
    ensure!(backend.read_tainted(&second).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn scan_corruption_preserves_earlier_rows_and_the_corrupt_rows_metadata() -> anyhow::Result<()>
{
    let backend = tmp_backend()?;
    let prefix = p("state://observation/corrupt")?;
    let first = prefix.clone().try_push_literal("a")?;
    let second = prefix.clone().try_push_literal("b")?;
    let first_taint = protected("state://private/first")?;
    let second_taint = protected("state://private/second")?;
    let mut expected = first_taint.clone();
    expected.union(&second_taint);
    backend
        .write_set_tainted(&first, Value::null(), first_taint.clone())
        .await?;
    let malformed = replace_payload(
        encode_envelope(&Value::null(), &second_taint)?,
        b"invalid-value",
    )?;
    replace_current(&backend, &second, &malformed)?;
    ensure!(
        backend
            .read_tainted(&second)
            .await
            .err()
            .context("corrupt point read succeeded")?
            .taint
            == second_taint
    );
    let failure = backend
        .query(&xolotl_state::StateScan::new(prefix.clone()))
        .await
        .err()
        .context("corrupt scan succeeded")?;
    ensure!(failure.taint == expected && matches!(failure.error, StateError::Serde(_)));
    replace_current(&backend, &second, b"invalid-prefix")?;
    let failure = backend
        .query(&xolotl_state::StateScan::new(prefix))
        .await
        .err()
        .context("invalid prefix accepted")?;
    ensure!(failure.taint == first_taint);
    Ok(())
}

#[tokio::test]
async fn history_filtering_and_late_corruption_preserve_observed_sources() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://observation/history")?;
    let first_taint = protected("state://private/history-first")?;
    let second_taint = protected("state://private/history-second")?;
    let mut expected = first_taint.clone();
    expected.union(&second_taint);
    backend
        .write_set_tainted(&path, Value::null(), first_taint)
        .await?;
    backend
        .write_set_tainted(&path, Value::null(), second_taint)
        .await?;
    let page = backend
        .history(&xolotl_state::StateHistoryQuery::new(path.clone(), 0, 1))
        .await?;
    ensure!(page.entries.is_empty() && page.taint == expected);
    let history = raw_history(&backend.db)?;
    let (first_key, first_bytes) = history.first().context("missing first history record")?;
    let mut query = xolotl_state::StateHistoryQuery::new(path.clone(), 0, i64::MAX);
    query.limits.encoded_bytes = NonZeroUsize::new(first_key.len() + first_bytes.len())
        .context("empty first history record")?;
    let page = backend.history(&query).await?;
    ensure!(page.entries.len() == 1 && page.taint == expected);
    query.cursor = page.next;
    query.limits.encoded_bytes = NonZeroUsize::MIN;
    let failure = backend
        .history(&query)
        .await
        .err()
        .context("oversized history accepted")?;
    ensure!(matches!(failure.error, StateError::RowTooLarge(_)));
    ensure!(failure.taint == protected("state://private/history-second")?);
    let (key, bytes) = history.get(1).context("missing second history record")?;
    let malformed = replace_payload(bytes.clone(), b"invalid-history")?;
    let txn = backend.db.begin_write()?;
    txn.open_table(STATE_HISTORY_TABLE)?
        .insert(key.as_slice(), malformed.as_slice())?;
    txn.commit()?;
    let failure = backend
        .history(&xolotl_state::StateHistoryQuery::new(
            path.clone(),
            0,
            i64::MAX,
        ))
        .await
        .err()
        .context("corrupt history page succeeded")?;
    ensure!(failure.taint == expected);
    let failure = backend
        .read_at(&path, i64::MAX)
        .await
        .err()
        .context("corrupt historical read succeeded")?;
    ensure!(failure.taint == expected);
    Ok(())
}
