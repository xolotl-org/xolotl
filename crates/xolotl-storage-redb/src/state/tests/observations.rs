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

fn oversized_header(format: &[u8; 4], bytes: usize) -> Vec<u8> {
    let mut record = vec![b'x'; bytes];
    record[..4].copy_from_slice(format);
    record[4..12].copy_from_slice(&(bytes as u64 - 12).to_le_bytes());
    record
}

#[tokio::test]
async fn scoped_pages_ignore_corrupt_neighbors_and_filtered_payloads() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let prefix = p("state://scope")?;
    let inside = p("state://scope/a")?;
    let outside = p("state://scope-b/a")?;
    let expected = protected("state://private/inside")?;
    backend
        .write_set_tainted(&inside, Value::null(), expected.clone())
        .await?;
    backend.write_set(&outside, Value::null()).await?;
    replace_current(&backend, &outside, b"invalid-current")?;
    let history = raw_history(&backend.db)?;
    let txn = backend.db.begin_write()?;
    {
        let mut table = txn.open_table(STATE_HISTORY_TABLE)?;
        for (key, bytes) in history {
            let (path, _) = history_key_parts(&key)?;
            if path == outside {
                table.insert(key.as_slice(), b"invalid-history".as_slice())?;
            } else {
                let malformed = replace_payload(bytes, b"invalid-event-payload")?;
                table.insert(key.as_slice(), malformed.as_slice())?;
            }
        }
    }
    txn.commit()?;
    let current = backend
        .query(&xolotl_state::StateScan::new(prefix.clone()))
        .await?;
    ensure!(current.entries.len() == 1 && current.examined == 1);
    ensure!(current.taint == expected);
    let filtered = backend
        .history(&xolotl_state::StateHistoryQuery::new(prefix.clone(), 0, 1))
        .await?;
    ensure!(filtered.entries.is_empty() && filtered.examined == 1);
    ensure!(filtered.taint == expected && filtered.encoded_bytes > 0);
    let failure = backend
        .history(&xolotl_state::StateHistoryQuery::new(prefix, 0, i64::MAX))
        .await
        .err()
        .context("matching corrupt history payload accepted")?;
    ensure!(failure.taint == expected);
    ensure!(matches!(failure.error, StateError::Serde(_)));
    Ok(())
}

#[tokio::test]
async fn bounded_comparison_rejects_replaced_raw_row_before_decode() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://observation/bounded-cas")?;
    let original_taint = protected("state://private/bounded-cas")?;
    let incoming_taint = TaintSet::of(TaintSource::ModelOutput);
    let original = Value::bytes(vec![7; 4096]);
    backend
        .write_set_tainted(&path, original.clone(), original_taint.clone())
        .await?;
    let encoded_bytes = {
        let txn = backend.db.begin_read()?;
        let table = txn.open_table(STATE_VALUES_TABLE)?;
        path.to_string().len()
            + table
                .get(path.to_string().as_str())?
                .context("missing current row")?
                .value()
                .len()
    };
    let exact = NonZeroUsize::new(encoded_bytes).context("exact budget")?;
    let mismatch = backend
        .compare_set_bounded(
            &path,
            Some(Value::null()),
            TaintedValue::new(Value::integer(1), incoming_taint.clone()),
            exact,
        )
        .await
        .err()
        .context("bounded mismatch succeeded")?;
    ensure!(
        matches!(mismatch.error, StateError::CasFailed { actual, .. } if actual.as_deref() == Some(&original))
            && mismatch.taint.contains_all(&original_taint)
            && mismatch.taint.contains_all(&incoming_taint)
    );
    let commit = backend
        .compare_set_bounded(
            &path,
            Some(original.clone()),
            TaintedValue::new(Value::integer(9), incoming_taint.clone()),
            exact,
        )
        .await?;
    ensure!(commit.taint.contains_all(&original_taint));
    ensure!(commit.taint.contains_all(&incoming_taint));
    let stored = backend.read_tainted(&path).await?;
    let stored_value = stored
        .value
        .clone()
        .context("bounded comparison did not commit")?;
    ensure!(stored_value == Value::integer(9));
    ensure!(stored.taint.contains_all(&original_taint));
    ensure!(stored.taint.contains_all(&incoming_taint));

    // This replacement models another writer between a bounded lookup and
    // the conditional commit. Its malformed provenance must not be decoded.
    let replacement = oversized_header(b"XSV1", 4096);
    replace_current(&backend, &path, &replacement)?;
    let history_before = raw_history(&backend.db)?;
    let failure = backend
        .compare_set_bounded(
            &path,
            Some(original.clone()),
            TaintedValue::new(Value::integer(2), incoming_taint.clone()),
            NonZeroUsize::new(1024).context("bounded budget")?,
        )
        .await
        .err()
        .context("oversized comparison decoded current row")?;
    ensure!(
        matches!(failure.error, StateError::PointTooLarge(row) if !row.provenance_observed)
            && failure.taint == incoming_taint
    );
    let failure = backend
        .compare_delete_bounded(
            &path,
            Some(original),
            incoming_taint.clone(),
            NonZeroUsize::new(1024).context("bounded budget")?,
        )
        .await
        .err()
        .context("oversized delete decoded current row")?;
    ensure!(
        matches!(failure.error, StateError::PointTooLarge(row) if !row.provenance_observed)
            && failure.taint == incoming_taint
    );
    let txn = backend.db.begin_read()?;
    let table = txn.open_table(STATE_VALUES_TABLE)?;
    ensure!(
        table
            .get(path.to_string().as_str())?
            .context("missing replacement")?
            .value()
            == replacement
    );
    ensure!(raw_history(&backend.db)? == history_before);
    Ok(())
}

#[tokio::test]
async fn pages_reject_oversized_provenance_headers_before_parsing() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let prefix = p("state://observation/header")?;
    let first = prefix.clone().try_push_literal("a")?;
    let second = prefix.clone().try_push_literal("b")?;
    let first_taint = protected("state://private/first-header")?;
    backend
        .write_set_tainted(&first, Value::null(), first_taint.clone())
        .await?;
    replace_current(&backend, &second, &oversized_header(b"XSV1", 4096))?;
    let mut scan = xolotl_state::StateScan::new(prefix);
    scan.limits.encoded_bytes = NonZeroUsize::new(1024).context("page budget")?;
    let partial = backend.query(&scan).await?;
    ensure!(partial.entries.len() == 1 && partial.entries[0].0 == first);
    ensure!(partial.taint == first_taint && partial.examined == 2);
    scan.cursor = partial.next;
    let failure = backend
        .query(&scan)
        .await
        .err()
        .context("oversized current provenance was parsed")?;
    ensure!(failure.taint.is_pristine());
    ensure!(matches!(
        failure.error,
        StateError::RowTooLarge(row) if row.path == second && !row.provenance_observed
            && row.retry == Some(xolotl_state::StateCursor(first.to_string().into_bytes()))
    ));

    let history_path = p("state://observation/history-header")?;
    let history_taint = protected("state://private/first-history-header")?;
    backend
        .write_set_tainted(&history_path, Value::integer(1), history_taint.clone())
        .await?;
    backend.write_set(&history_path, Value::integer(2)).await?;
    let history = raw_history(&backend.db)?;
    let (key, _) = history.last().context("missing history row")?;
    let retry_key = history
        .get(history.len() - 2)
        .context("missing earlier history row")?
        .0
        .clone();
    let txn = backend.db.begin_write()?;
    txn.open_table(STATE_HISTORY_TABLE)?
        .insert(key.as_slice(), oversized_header(b"XSH1", 4096).as_slice())?;
    txn.commit()?;
    let mut scan = xolotl_state::StateHistoryQuery::new(history_path.clone(), 0, i64::MAX);
    let mut retry_cursor = super::super::read::history_cursor_scope(&scan, i64::MIN)?;
    retry_cursor.extend_from_slice(&retry_key);
    scan.limits.encoded_bytes = NonZeroUsize::new(1024).context("history page budget")?;
    let partial = backend.history(&scan).await?;
    ensure!(partial.entries.len() == 1 && partial.entries[0].event.path() == &history_path);
    ensure!(partial.taint == history_taint && partial.examined == 2);
    scan.cursor = partial.next;
    let failure = backend
        .history(&scan)
        .await
        .err()
        .context("oversized historical provenance was parsed")?;
    ensure!(failure.taint.is_pristine());
    ensure!(matches!(
        failure.error,
        StateError::RowTooLarge(row) if row.path == history_path && !row.provenance_observed
            && row.retry == Some(xolotl_state::StateCursor(retry_cursor))
    ));
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
    // Each completed transaction carries the sources it observed. A later
    // deletion cannot erase those sources from the already returned failures.
    let conflict = backend
        .write_cas_tainted(&path, None, Value::null(), TaintSet::author())
        .await;
    let append = backend.write_append(&path, Value::null()).await;
    let deletion = backend.write_compare_delete(&path, None).await;
    backend.write_delete(&path).await?;
    for result in [conflict, append, deletion] {
        let failure = result.err().context("conflicting mutation succeeded")?;
        ensure!(failure.taint.sources().contains(&taint.sources()[0]));
        ensure!(!failure.to_string().contains(secret));
        ensure!(!format!("{failure:?}").contains(secret));
        if let StateError::CasFailed { actual, .. } = failure.error {
            ensure!(actual.as_deref().and_then(Value::as_str) == Some(secret));
        }
    }
    ensure!(backend.read_tainted(&path).await?.value.is_none());
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
    ensure!(
        backend.read_tainted(&path).await?
            == xolotl_state::StateObservation::from(TaintedValue::new(Value::null(), current))
    );
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
    let failure = backend
        .query(&query)
        .await
        .err()
        .context("oversized row accepted")?;
    ensure!(failure.taint == taint);
    ensure!(matches!(failure.error, StateError::RowTooLarge(row) if row.path == second));
    let deferred = backend.query(&query);
    // Deletion also needs no value decoder and still reports observed sources.
    ensure!(backend.write_delete(&second).await?.taint == taint);
    // An unpolled read has not entered redb and observes the committed delete.
    let after_delete = deferred.await?;
    ensure!(after_delete.entries.is_empty() && after_delete.taint == taint);
    ensure!(after_delete.examined == 1 && after_delete.encoded_bytes > 0);
    ensure!(backend.read_tainted(&second).await?.value.is_none());
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
    query.limits.encoded_bytes = NonZeroUsize::new(first_key.len() + first_bytes.len() + 1)
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
    ensure!(matches!(
        failure.error,
        StateError::RowTooLarge(row) if !row.provenance_observed
    ));
    ensure!(failure.taint.is_pristine());
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

#[tokio::test]
async fn historical_point_read_ignores_later_corrupt_record() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://observation/historical-point")?;
    let first_taint = protected("state://private/point-first")?;
    let second_taint = protected("state://private/point-second")?;
    backend
        .write_set_tainted(&path, Value::integer(1), first_taint.clone())
        .await?;
    backend
        .write_set_tainted(&path, Value::integer(2), second_taint.clone())
        .await?;
    let history = backend
        .history(&xolotl_state::StateHistoryQuery::new(
            path.clone(),
            0,
            i64::MAX,
        ))
        .await?;
    ensure!(history.entries.len() == 2);
    let first_time = history.entries[0].at_millis;
    let second_time = history.entries[1].at_millis;
    let rows = raw_history(&backend.db)?;
    let (second_key, second_bytes) = rows.get(1).context("missing later history row")?;
    let corrupt = replace_payload(second_bytes.clone(), b"invalid-history")?;
    let txn = backend.db.begin_write()?;
    txn.open_table(STATE_HISTORY_TABLE)?
        .insert(second_key.as_slice(), corrupt.as_slice())?;
    txn.commit()?;

    ensure!(
        backend.read_at(&path, first_time).await?
            == xolotl_state::StateObservation::from(TaintedValue::new(
                Value::integer(1),
                first_taint.clone()
            ))
    );
    let failure = backend
        .read_at(&path, second_time)
        .await
        .err()
        .context("corrupt record at requested time was accepted")?;
    ensure!(matches!(failure.error, StateError::Serde(_)));
    ensure!(failure.taint == first_taint.merged(&second_taint));
    Ok(())
}

#[tokio::test]
async fn retention_keeps_earlier_sources_when_later_record_is_corrupt() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://observation/trim-corrupt")?;
    let first_taint = protected("state://private/trim-first")?;
    backend
        .write_set_tainted(&path, Value::integer(1), first_taint.clone())
        .await?;
    backend.write_set(&path, Value::integer(2)).await?;
    let rows = raw_history(&backend.db)?;
    let (second_key, _) = rows.get(1).context("missing later history row")?;
    let txn = backend.db.begin_write()?;
    txn.open_table(STATE_HISTORY_TABLE)?
        .insert(second_key.as_slice(), b"invalid-prefix".as_slice())?;
    txn.commit()?;
    let before = raw_history(&backend.db)?;
    let floor = history_millis(&backend.db)? + 1;

    let failure = backend
        .trim_before(floor, xolotl_state::StateHistoryTrimLimits::default())
        .await
        .err()
        .context("corrupt later history row was trimmed")?;
    ensure!(matches!(failure.error, StateError::Serde(_)));
    ensure!(failure.taint == first_taint);
    ensure!(backend.retained_from().await? == i64::MIN);
    ensure!(raw_history(&backend.db)? == before);
    Ok(())
}

#[tokio::test]
async fn retention_keeps_earlier_sources_when_later_index_is_invalid() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://observation/trim-index")?;
    let first_taint = protected("state://private/trim-index-first")?;
    backend
        .write_set_tainted(&path, Value::integer(1), first_taint.clone())
        .await?;
    backend.write_set(&path, Value::integer(2)).await?;
    let txn = backend.db.begin_write()?;
    {
        let mut index = txn.open_table(crate::schema::STATE_HISTORY_TIME_INDEX_TABLE)?;
        let (key, _) = index.pop_last()?.context("missing later time index")?;
        let mut invalid = key.value().to_vec();
        *invalid.last_mut().context("empty time index key")? ^= 1;
        drop(key);
        index.insert(invalid.as_slice(), &[][..])?;
    }
    txn.commit()?;
    let before = raw_history(&backend.db)?;
    let floor = history_millis(&backend.db)? + 1;

    let failure = backend
        .trim_before(floor, xolotl_state::StateHistoryTrimLimits::default())
        .await
        .err()
        .context("invalid later time index was trimmed")?;
    ensure!(matches!(failure.error, StateError::Backend(_)));
    ensure!(failure.taint == first_taint);
    ensure!(backend.retained_from().await? == i64::MIN);
    ensure!(raw_history(&backend.db)? == before);
    Ok(())
}
