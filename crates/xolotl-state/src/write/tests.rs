use super::*;
use alloc::{vec, vec::Vec};
use anyhow::{Result, ensure};
use xolotl_types::TaintSource;

fn sources(path: &Path) -> (TaintSet, TaintSet) {
    (
        TaintSet::of(TaintSource::Protected { path: path.clone() }),
        TaintSet::of(TaintSource::ModelOutput),
    )
}

#[test]
fn absent_observation_controls_dependent_events_but_not_independent_set() -> Result<()> {
    let path = Path::parse("state://mutation/absence")?;
    let (current, incoming) = sources(&path);
    let item = Value::integer(7);
    let mutations = [
        StateMutation::Set(TaintedValue::new(item.clone(), incoming.clone())),
        StateMutation::CompareSet {
            expected: None,
            value: TaintedValue::new(item.clone(), incoming.clone()),
        },
        StateMutation::Append(TaintedValue::new(item.clone(), incoming.clone())),
        StateMutation::Merge {
            value: TaintedValue::new(item.clone(), incoming.clone()),
            rule: MergeRule::Deep,
        },
    ];
    for (index, mutation) in mutations.into_iter().enumerate() {
        let event = mutation
            .prepare_event(&path, None, current.clone())?
            .ok_or_else(|| anyhow::anyhow!("value mutation produced no event"))?;
        let expected = if index == 0 {
            incoming.clone()
        } else {
            incoming.clone().merged(&current)
        };
        ensure!(event.taint().contains_all(&expected));
        ensure!(expected.contains_all(event.taint()));
        match event {
            StateEvent::Set { value, .. } => ensure!(value == item),
            StateEvent::Append { item: actual, .. } => ensure!(actual == item),
            other => anyhow::bail!("unexpected value mutation: {other:?}"),
        }
    }
    Ok(())
}

#[test]
fn comparisons_distinguish_absence_from_null_and_retain_failure_sources() -> Result<()> {
    let path = Path::parse("state://mutation/compare")?;
    let (current, incoming) = sources(&path);
    let expected_sources = current.clone().merged(&incoming);
    for mutation in [
        StateMutation::CompareSet {
            expected: Some(Value::null()),
            value: TaintedValue::new(Value::integer(1), incoming.clone()),
        },
        StateMutation::CompareDelete {
            expected: Some(Value::null()),
            taint: incoming.clone(),
        },
    ] {
        let failure = mutation
            .prepare_event(&path, None, current.clone())
            .err()
            .ok_or_else(|| anyhow::anyhow!("stored null matched absence"))?;
        ensure!(
            matches!(failure.error, StateError::CasFailed { actual: None, expected: Some(ref value), .. } if **value == Value::null())
        );
        ensure!(failure.taint.contains_all(&expected_sources));
        ensure!(expected_sources.contains_all(&failure.taint));
    }
    for mutation in [
        StateMutation::Delete(incoming.clone()),
        StateMutation::CompareDelete {
            expected: None,
            taint: incoming.clone(),
        },
    ] {
        ensure!(
            mutation
                .prepare_event(&path, None, current.clone())?
                .is_none()
        );
    }
    let stored_null = Value::null();
    let event = StateMutation::CompareDelete {
        expected: Some(stored_null.clone()),
        taint: incoming,
    }
    .prepare_event(&path, Some(&stored_null), current)?
    .ok_or_else(|| anyhow::anyhow!("stored null deletion produced no event"))?;
    ensure!(matches!(event, StateEvent::Delete { .. }));
    ensure!(event.taint().contains_all(&expected_sources));
    Ok(())
}

#[test]
fn append_metadata_matches_resident_preparation_with_recorded_sources() -> Result<()> {
    let path = Path::parse("state://mutation/append-metadata")?;
    let incoming = TaintSet::from_recorded_sources(vec![
        TaintSource::AuthorConstant,
        TaintSource::AuthorConstant,
    ]);
    let current_taint = TaintSet::from_recorded_sources(vec![
        TaintSource::ModelOutput,
        TaintSource::AuthorConstant,
        TaintSource::ModelOutput,
    ]);
    let observed = incoming.clone().merged(&current_taint);
    for current in [None, Some(Value::list(Vec::new())), Some(Value::null())] {
        let item = TaintedValue::new(Value::integer(7), incoming.clone());
        let resident = StateMutation::Append(item.clone()).prepare_event(
            &path,
            current.as_ref(),
            observed.clone(),
        );
        let metadata = StateMutation::prepare_append_event(
            &path,
            item,
            current.as_ref().map(|value| value.as_list().is_some()),
            observed.clone(),
        );
        match (resident, metadata) {
            (Ok(Some(resident)), Ok(metadata)) => {
                ensure!(resident == metadata);
                ensure!(metadata.taint() == &observed);
                ensure!(core::ptr::eq(
                    metadata.taint().sources(),
                    observed.sources()
                ));
            }
            (Err(resident), Err(metadata)) => {
                ensure!(resident.taint == metadata.taint && metadata.taint == observed);
                ensure!(resident.error.to_string() == metadata.error.to_string());
            }
            _ => anyhow::bail!("Append metadata and resident preparation differed"),
        }
    }
    Ok(())
}

#[test]
fn prepared_events_share_already_accumulated_sources() -> Result<()> {
    let path = Path::parse("state://mutation/source-sharing")?;
    let (current, incoming) = sources(&path);
    let observed = incoming.clone().merged(&current);
    for mutation in [
        StateMutation::CompareSet {
            expected: None,
            value: TaintedValue::new(Value::integer(1), incoming.clone()),
        },
        StateMutation::Append(TaintedValue::new(Value::integer(1), incoming.clone())),
        StateMutation::Merge {
            value: TaintedValue::new(Value::integer(1), incoming),
            rule: MergeRule::Deep,
        },
    ] {
        let event = mutation
            .prepare_event(&path, None, observed.clone())?
            .ok_or_else(|| anyhow::anyhow!("value mutation produced no event"))?;
        ensure!(core::ptr::eq(event.taint().sources(), observed.sources()));
    }
    Ok(())
}
