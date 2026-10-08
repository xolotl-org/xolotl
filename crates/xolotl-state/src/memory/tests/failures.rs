use super::*;

#[test]
fn bounded_point_read_measures_borrowed_value_before_copying() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://bounded/item")?;
        let child = p("state://bounded/item/child")?;
        let taint = TaintSet::of(TaintSource::Protected { path: path.clone() });
        let value = Value::bytes(vec![7; 4096]);
        backend
            .write_set_tainted(&path, value.clone(), taint.clone())
            .await?;
        backend.write_set(&child, Value::null()).await?;
        let encoded_bytes =
            crate::host::encoded_size(&TaintedValue::new(value.clone(), taint.clone()))?
                + path.to_string().len();
        let exact = NonZeroUsize::new(encoded_bytes).context("encoded size")?;
        ensure!(
            backend.read_tainted_bounded(&path, exact).await?
                == crate::StateObservation::from(TaintedValue::new(value, taint.clone()))
        );
        let too_small = NonZeroUsize::new(encoded_bytes - 1).context("smaller budget")?;
        let failure = backend
            .read_tainted_bounded(&path, too_small)
            .await
            .err()
            .context("oversized point read succeeded")?;
        ensure!(failure.taint == taint);
        let StateError::PointTooLarge(row) = failure.error else {
            bail!("unexpected bounded point error")
        };
        ensure!(
            row.path == path
                && row.encoded_bytes == encoded_bytes
                && row.limit_encoded_bytes == too_small
                && row.provenance_observed
        );
        ensure!(
            backend
                .read_tainted_bounded(&p("state://bounded")?, too_small)
                .await?
                .value
                .is_none(),
            "exact point read returned a descendant"
        );
        Ok(())
    })
}

#[test]
fn bounded_comparison_measures_current_inside_commit_and_retains_sources() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://bounded/compare")?;
        let current_taint = TaintSet::of(TaintSource::Protected {
            path: p("state://private/current")?,
        });
        let incoming_taint = TaintSet::of(TaintSource::ModelOutput);
        let current = Value::bytes(vec![3; 4096]);
        backend
            .write_set_tainted(&path, current.clone(), current_taint.clone())
            .await?;
        let encoded_bytes =
            crate::host::encoded_size(&TaintedValue::new(current.clone(), current_taint.clone()))?
                + path.to_string().len();
        let too_small = NonZeroUsize::new(encoded_bytes - 1).context("smaller budget")?;
        let oversized = backend
            .compare_set_bounded(
                &path,
                Some(Value::null()),
                TaintedValue::new(Value::integer(1), incoming_taint.clone()),
                too_small,
            )
            .await
            .err()
            .context("oversized bounded comparison succeeded")?;
        let StateError::PointTooLarge(row) = oversized.error else {
            bail!("expected typed oversized comparison")
        };
        ensure!(
            row.path == path
                && row.encoded_bytes == encoded_bytes
                && row.provenance_observed
                && oversized.taint == current_taint.clone().merged(&incoming_taint)
        );
        let failed_delete = backend
            .write_compare_delete_bounded(&path, Some(Value::null()), too_small)
            .await
            .err()
            .context("oversized bounded deletion succeeded")?;
        ensure!(
            matches!(failed_delete.error, StateError::PointTooLarge(_))
                && failed_delete.taint == current_taint
        );
        let exact = NonZeroUsize::new(encoded_bytes).context("exact budget")?;
        let mismatch = backend
            .compare_set_bounded(
                &path,
                Some(Value::null()),
                TaintedValue::new(Value::integer(2), incoming_taint.clone()),
                exact,
            )
            .await
            .err()
            .context("mismatching bounded comparison succeeded")?;
        ensure!(
            matches!(mismatch.error, StateError::CasFailed { actual, .. } if actual.as_deref() == Some(&current))
                && mismatch.taint.contains_all(&current_taint)
                && mismatch.taint.contains_all(&incoming_taint)
        );
        ensure!(
            backend.read_tainted(&path).await?
                == crate::StateObservation::from(TaintedValue::new(
                    current.clone(),
                    current_taint.clone()
                ))
        );
        let commit = backend
            .compare_set_bounded(
                &path,
                Some(current),
                TaintedValue::new(Value::integer(3), incoming_taint.clone()),
                exact,
            )
            .await?;
        ensure!(commit.taint.contains_all(&current_taint));
        ensure!(commit.taint.contains_all(&incoming_taint));
        let stored = backend.read_tainted(&path).await?;
        let stored_value = stored
            .value
            .clone()
            .context("bounded comparison did not commit")?;
        ensure!(stored_value == Value::integer(3));
        ensure!(stored.taint.contains_all(&current_taint));
        ensure!(stored.taint.contains_all(&incoming_taint));
        let deleted = backend
            .write_compare_delete_bounded(&path, Some(Value::integer(3)), exact)
            .await?;
        ensure!(deleted.taint == stored.taint);
        ensure!(backend.read_tainted(&path).await?.value.is_none());
        Ok(())
    })
}

#[test]
fn failed_atomic_observation_survives_replacement_and_deletion() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://errors/value")?;
        let secret = "private-record-content";
        let original = TaintSet::of(TaintSource::Protected {
            path: p("state://private/source")?,
        });
        backend
            .write_set_tainted(&path, Value::string(secret.into()), original.clone())
            .await?;
        // Ready captures the commit result synchronously. Change the live State
        // before observing that result to model a delayed error consumer.
        let conflict = backend.write_cas_tainted(&path, None, Value::null(), TaintSet::author());
        let append = backend.write_append(&path, Value::null());
        let removal = backend.write_compare_delete(&path, None);
        backend.write_delete(&path).await?;
        for failure in [conflict.await, append.await, removal.await] {
            let failure = failure.err().context("conflicting mutation succeeded")?;
            ensure!(failure.taint.sources().contains(&original.sources()[0]));
            ensure!(!failure.to_string().contains(secret));
            ensure!(!format!("{failure:?}").contains(secret));
            ensure!(!format!("{:?}", failure.error).contains("private/source"));
            if let StateError::CasFailed { actual, .. } = failure.error {
                ensure!(actual.as_deref().and_then(Value::as_str) == Some(secret));
            }
        }
        ensure!(backend.read_tainted(&path).await?.value.is_none());
        Ok(())
    })
}

#[test]
fn a_deferred_page_row_and_its_later_error_keep_the_same_sources() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let prefix = p("state://page")?;
        let first = prefix.clone().try_push_literal("a")?;
        let second = prefix.clone().try_push_literal("b")?;
        let protected = TaintSet::of(TaintSource::Protected {
            path: second.clone(),
        });
        backend.write_set(&first, Value::null()).await?;
        backend
            .write_set_tainted(&second, Value::bytes(vec![7; 4096]), protected.clone())
            .await?;
        let mut query = StateScan::new(prefix);
        query.limits.encoded_bytes = NonZeroUsize::new(1024).context("page budget")?;
        let page = backend.query(&query).await?;
        ensure!(page.entries.len() == 1 && page.entries[0].0 == first);
        ensure!(page.taint == protected);
        query.cursor = page.next;
        let deferred = backend.query(&query);
        backend.write_delete(&second).await?;
        let failure = deferred.await.err().context("oversized row succeeded")?;
        ensure!(failure.taint == protected);
        let StateError::RowTooLarge(row) = failure.error else {
            bail!("unexpected page failure")
        };
        ensure!(row.path == second && row.encoded_bytes > query.limits.encoded_bytes.get());
        ensure!(backend.read_tainted(&second).await?.value.is_none());
        Ok(())
    })
}

#[test]
fn history_pages_preserve_filtered_and_oversized_observations() -> anyhow::Result<()> {
    for_backends(&[MemoryHistory::Full], |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://history/errors")?;
        let protected = TaintSet::of(TaintSource::Protected { path: path.clone() });
        backend
            .write_set_tainted(&path, Value::bytes(vec![7; 4096]), protected.clone())
            .await?;
        let filtered = backend
            .history(&StateHistoryQuery::new(path.clone(), 0, 1))
            .await?;
        ensure!(
            filtered.entries.is_empty()
                && filtered.taint == protected
                && filtered.encoded_bytes > 0
        );
        let mut query = StateHistoryQuery::new(path, 0, i64::MAX);
        query.limits.encoded_bytes = NonZeroUsize::MIN;
        let failure = backend
            .history(&query)
            .await
            .err()
            .context("oversized history succeeded")?;
        ensure!(
            matches!(failure.error, StateError::RowTooLarge(row) if !row.provenance_observed)
                && failure.taint.is_pristine()
        );
        Ok(())
    })
}

#[test]
fn serialization_diagnostics_require_explicit_cause_inspection() {
    let failure = crate::StateFailure::new(
        StateError::Serde("private-serialized-data".into()),
        TaintSet::author(),
    );
    assert!(!format!("{failure:?}").contains("private-serialized-data"));
    assert!(!failure.to_string().contains("private-serialized-data"));
    assert!(
        matches!(failure.error, StateError::Serde(reason) if reason == "private-serialized-data")
    );
}
