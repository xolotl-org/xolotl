use super::*;

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
        ensure!(backend.read_tainted(&path).await?.is_none());
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
        ensure!(backend.read_tainted(&second).await?.is_none());
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
        ensure!(filtered.entries.is_empty() && filtered.taint == protected);
        let mut query = StateHistoryQuery::new(path, 0, i64::MAX);
        query.limits.encoded_bytes = NonZeroUsize::MIN;
        let failure = backend
            .history(&query)
            .await
            .err()
            .context("oversized history succeeded")?;
        ensure!(matches!(failure.error, StateError::RowTooLarge(_)) && failure.taint == protected);
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
