use super::*;

#[test]
fn already_over_limit_usage_may_shrink_but_each_dimension_must_not_grow() -> anyhow::Result<()> {
    let usage = AbsenceUsage {
        records: 2,
        encoded_bytes: 100,
    };
    let limits = InMemoryOptions {
        absence_limits: crate::AbsenceLimits {
            records: Some(0),
            encoded_bytes: Some(0),
        },
        ..Default::default()
    };
    let before = CurrentRecord::Absent {
        taint: TaintSet::author(),
        encoded_bytes: 50,
    };
    let same = CurrentRecord::Absent {
        taint: TaintSet::author(),
        encoded_bytes: 50,
    };
    let smaller = CurrentRecord::Absent {
        taint: TaintSet::author(),
        encoded_bytes: 49,
    };
    let larger = CurrentRecord::Absent {
        taint: TaintSet::author(),
        encoded_bytes: 51,
    };
    ensure!(usage.replacing(Some(&before), Some(&same), &limits)? == usage);
    ensure!(
        usage
            .replacing(Some(&before), Some(&smaller), &limits)?
            .encoded_bytes
            == 99
    );
    ensure!(
        usage
            .replacing(Some(&before), Some(&larger), &limits)
            .is_err()
    );
    ensure!(
        usage.replacing(Some(&before), None, &limits)?
            == AbsenceUsage {
                records: 1,
                encoded_bytes: 50
            }
    );
    let unlimited = InMemoryOptions {
        absence_limits: crate::AbsenceLimits {
            records: None,
            encoded_bytes: None,
        },
        ..Default::default()
    };
    ensure!(
        usage.replacing(None, Some(&larger), &unlimited)?
            == AbsenceUsage {
                records: 3,
                encoded_bytes: 151
            }
    );
    Ok(())
}

#[test]
fn absence_count_rejection_and_reconstruction_are_atomic() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |mut options| async move {
        options.absence_limits.records = Some(1);
        let backend = InMemoryBackend::with_options(options)?;
        let first = p("state://absence/a")?;
        let second = p("state://absence/b")?;
        let input = TaintSet::of(TaintSource::ModelOutput);
        let control = TaintSet::author();
        backend
            .write_set_tainted(&first, Value::integer(1), input.clone())
            .await?;
        backend
            .write_set_tainted(&second, Value::integer(2), input.clone())
            .await?;
        backend.write_delete(&first).await?;
        let usage = backend.inner.read().absence;
        ensure!(usage.records == 1 && usage.encoded_bytes > 0);
        let before = backend.inner.read().history.len();
        let mut events = backend.subscribe(&p("state://absence/**")?).await?;
        let rejected = backend.write_delete_tainted(&second, control.clone()).await;
        let Err(failure) = rejected else {
            bail!("over-limit deletion succeeded")
        };
        ensure!(
            matches!(&failure.error, StateError::Backend(reason) if reason == "state absence capacity exhausted")
        );
        ensure!(failure.taint == control.clone().merged(&input));
        ensure!(backend.read_at(&second, 0).await?.value == Some(Value::integer(2)));
        ensure!(backend.inner.read().absence == usage);
        ensure!(backend.inner.read().history.len() == before);
        ensure!(matches!(
            events.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));

        let no_op = backend
            .write_delete_tainted(&first, control.clone())
            .await?;
        ensure!(no_op.taint == control.clone().merged(&input));
        ensure!(backend.read_at(&first, 0).await?.taint == input);
        ensure!(backend.inner.read().absence == usage);
        ensure!(backend.inner.read().history.len() == before);
        ensure!(matches!(
            events.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        let conflict = backend
            .write_cas(&first, Some(Value::integer(1)), Value::integer(3))
            .await;
        let Err(failure) = conflict else {
            bail!("comparison ignored absence")
        };
        ensure!(matches!(
            failure.error,
            StateError::CasFailed { actual: None, .. }
        ));
        ensure!(failure.taint == input);
        ensure!(backend.inner.read().absence == usage);

        if options.history == MemoryHistory::Full {
            let floor = backend.inner.read().last_history_millis + 1;
            backend
                .trim_before(floor, crate::StateHistoryTrimLimits::default())
                .await?;
            ensure!(backend.inner.read().history.is_empty());
            ensure!(backend.inner.read().absence == usage);
            ensure!(backend.read_at(&first, 0).await?.taint == input);
            ensure!(backend.write_delete(&second).await.is_err());
        }

        backend.write_cas(&first, None, Value::integer(3)).await?;
        ensure!(backend.read_at(&first, 0).await?.taint == input);
        ensure!(backend.inner.read().absence == AbsenceUsage::default());
        backend.write_delete(&second).await?;
        backend.write_set(&second, Value::null()).await?;
        ensure!(
            backend.read_at(&second, 0).await?
                == StateObservation {
                    value: Some(Value::null()),
                    taint: TaintSet::pristine(),
                }
        );
        ensure!(backend.inner.read().absence == AbsenceUsage::default());
        Ok(())
    })
}

#[test]
fn absence_bytes_charge_each_key_and_refuse_before_deleting() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |mut options| async move {
        let first = p("state://absence-bytes/a")?;
        let second = p("state://absence-bytes/b")?;
        let taint = TaintSet::of(TaintSource::Protected {
            path: p("state://private")?,
        });
        let observation = StateObservation {
            value: None,
            taint: taint.clone(),
        };
        let encoded_bytes = serde_json::to_vec(&observation)?.len() + first.to_string().len();
        options.absence_limits.encoded_bytes = Some(encoded_bytes);
        let backend = InMemoryBackend::with_options(options)?;
        for path in [&first, &second] {
            backend
                .write_set_tainted(path, Value::integer(1), taint.clone())
                .await?;
        }
        backend.write_delete(&first).await?;
        ensure!(
            backend.inner.read().absence
                == AbsenceUsage {
                    records: 1,
                    encoded_bytes
                }
        );
        let Err(failure) = backend.write_delete(&second).await else {
            bail!("shared sources were not charged per key")
        };
        ensure!(
            matches!(&failure.error, StateError::Backend(reason) if reason == "state absence capacity exhausted")
        );
        ensure!(backend.read_at(&second, 0).await?.value == Some(Value::integer(1)));
        ensure!(
            backend.inner.read().absence
                == AbsenceUsage {
                    records: 1,
                    encoded_bytes
                }
        );
        backend.write_set(&first, Value::integer(2)).await?;
        backend.write_delete(&second).await?;
        ensure!(
            backend.inner.read().absence
                == AbsenceUsage {
                    records: 1,
                    encoded_bytes
                }
        );

        options.absence_limits.encoded_bytes = Some(encoded_bytes - 1);
        let undersized = InMemoryBackend::with_options(options)?;
        undersized
            .write_set_tainted(&first, Value::integer(1), taint.clone())
            .await?;
        let Err(failure) = undersized.write_delete(&first).await else {
            bail!("under-budget deletion succeeded")
        };
        ensure!(
            matches!(&failure.error, StateError::Backend(reason) if reason == "state absence capacity exhausted")
        );
        ensure!(undersized.inner.read().absence == AbsenceUsage::default());
        ensure!(undersized.read_at(&first, 0).await?.value == Some(Value::integer(1)));
        options.absence_limits.records = Some(0);
        options.absence_limits.encoded_bytes = Some(0);
        let zero = InMemoryBackend::with_options(options)?;
        zero.write_set(&first, Value::integer(1)).await?;
        zero.write_delete(&first).await?;
        ensure!(zero.read_at(&first, 0).await? == StateObservation::default());
        ensure!(zero.inner.read().absence == AbsenceUsage::default());
        Ok(())
    })
}

#[test]
fn absent_pages_consume_work_and_bytes_without_returning_null_entries() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let paths = [p("state://absence-page/a")?, p("state://absence-page/b")?];
        let sources = [TaintSet::of(TaintSource::ModelOutput), TaintSet::author()];
        let mut sizes = Vec::new();
        for (path, taint) in paths.iter().zip(&sources) {
            backend
                .write_set_tainted(path, Value::null(), taint.clone())
                .await?;
            backend.write_delete(path).await?;
            sizes.push(
                serde_json::to_vec(&StateObservation {
                    value: None,
                    taint: taint.clone(),
                })?
                .len()
                    + path.to_string().len(),
            );
        }
        let mut query = StateScan::new(p("state://absence-page")?);
        query.limits.encoded_bytes = NonZeroUsize::new(sizes[0]).context("zero record size")?;
        let page = backend.query(&query).await?;
        ensure!(page.entries.is_empty() && page.next.is_some());
        ensure!(page.examined == 1 && page.encoded_bytes == sizes[0]);
        ensure!(page.taint == sources[0]);
        ensure!(page.next == Some(StateCursor(paths[0].to_string().into_bytes())));
        query.cursor = page.next;
        query.limits.encoded_bytes = NonZeroUsize::new(sizes[1] - 1).context("zero budget")?;
        let Err(failure) = backend.query(&query).await else {
            bail!("oversized absence was skipped")
        };
        let StateError::RowTooLarge(row) = failure.error else {
            bail!("wrong row error")
        };
        ensure!(row.path == paths[1] && row.encoded_bytes == sizes[1]);
        ensure!(row.provenance_observed && row.retry == query.cursor);
        ensure!(row.resume == StateCursor(paths[1].to_string().into_bytes()));
        ensure!(failure.taint == sources[1]);
        query.limits.encoded_bytes = NonZeroUsize::new(sizes[1]).context("zero record size")?;
        let terminal = backend.query(&query).await?;
        ensure!(terminal.entries.is_empty() && terminal.next.is_some());
        ensure!(terminal.examined == 1 && terminal.encoded_bytes == sizes[1]);
        ensure!(terminal.taint == sources[1]);
        query.cursor = terminal.next;
        let terminal = backend.query(&query).await?;
        ensure!(terminal.entries.is_empty() && terminal.next.is_none());
        ensure!(terminal.examined == 0 && terminal.encoded_bytes == 0);
        ensure!(terminal.taint.is_pristine());
        query.cursor = None;
        query.limits = crate::StatePageLimits::default();
        query.limits.examined = NonZeroUsize::MIN;
        let bounded = backend.query(&query).await?;
        ensure!(bounded.entries.is_empty() && bounded.examined == 1);
        ensure!(bounded.encoded_bytes == sizes[0] && bounded.taint == sources[0]);
        ensure!(bounded.next == Some(StateCursor(paths[0].to_string().into_bytes())));
        let Err(failure) = backend
            .read_tainted_bounded(&paths[0], NonZeroUsize::MIN)
            .await
        else {
            bail!("bounded read ignored absent record bytes")
        };
        ensure!(matches!(failure.error, StateError::PointTooLarge(ref row)
            if row.provenance_observed && row.encoded_bytes == sizes[0]));
        ensure!(failure.taint == sources[0]);
        Ok(())
    })
}
