use super::*;
use anyhow::{Result, ensure};
use xolotl_types::{TaintSource, TaintedValue, Value, ValueList};

#[test]
fn deletion_and_dependent_append_preserve_absence_until_independent_set() -> Result<()> {
    let path = Path::parse("state://history/absence")?;
    let protected = TaintSet::of(TaintSource::Protected { path: path.clone() });
    let deleted = TaintSet::of(TaintSource::ModelOutput);
    let expected = protected.clone().merged(&deleted);
    let mut current = StateObservation::from(TaintedValue::new(Value::integer(1), protected));
    apply_event(
        &mut current,
        &crate::StateEvent::Delete {
            path: path.clone(),
            taint: expected.clone(),
        },
    )?;
    ensure!(current.value.is_none() && current.taint == expected);
    let incoming = TaintSet::author();
    apply_event(
        &mut current,
        &crate::StateEvent::Append {
            path: path.clone(),
            item: Value::integer(7),
            taint: incoming.clone(),
        },
    )?;
    ensure!(current.value == Some(Value::from(ValueList::from_iter([Value::integer(7)]))));
    ensure!(current.taint == expected.merged(&incoming));
    apply_event(
        &mut current,
        &crate::StateEvent::Set {
            path,
            value: Value::null(),
            taint: TaintSet::pristine(),
        },
    )?;
    ensure!(current.value == Some(Value::null()) && current.taint.is_pristine());
    Ok(())
}

#[test]
fn invalid_prefix_append_preserves_the_absent_snapshot_and_observed_sources() -> Result<()> {
    let path = Path::parse("state://history/invalid-prefix")?;
    let protected = TaintSet::of(TaintSource::Protected { path: path.clone() });
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    let mut current = StateObservation {
        value: None,
        taint: protected.clone(),
    };
    let before = current.clone();
    let failure = apply_event(
        &mut current,
        &crate::StateEvent::DropPrefixAppend {
            path,
            removed: 1,
            item: Value::integer(1),
            taint: incoming.clone(),
        },
    )
    .err()
    .ok_or_else(|| anyhow::anyhow!("prefix append on absence succeeded"))?;
    ensure!(current == before);
    let expected = protected.merged(&incoming);
    ensure!(failure.taint.contains_all(&expected) && expected.contains_all(&failure.taint));
    Ok(())
}
