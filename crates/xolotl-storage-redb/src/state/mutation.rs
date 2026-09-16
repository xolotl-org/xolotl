//! One transaction owns the current-value observation, mutation, and history.

use super::*;

struct PreparedMutation {
    stored: Option<TaintedValue>,
    event: StateEvent,
}

impl PreparedMutation {
    fn set(path: &Path, stored: TaintedValue) -> Self {
        Self {
            event: StateEvent::Set {
                path: path.clone(),
                value: stored.value.clone(),
                taint: stored.taint.clone(),
            },
            stored: Some(stored),
        }
    }

    fn delete(path: &Path, taint: TaintSet) -> Self {
        Self {
            stored: None,
            event: StateEvent::Delete {
                path: path.clone(),
                taint,
            },
        }
    }
}

fn compare(
    path: &Path,
    expected: Option<Value>,
    current: Option<&TaintedValue>,
) -> StateResult<()> {
    if current.map(|stored| &stored.value) == expected.as_ref() {
        return Ok(());
    }
    Err(StateError::CasFailed {
        path: path.to_string(),
        expected: expected.map(Box::new),
        actual: current.map(|stored| Box::new(stored.value.clone())),
    }
    .into())
}

impl RedbStateBackend {
    fn commit_mutation(&self, path: &Path, mutation: StateMutation) -> StateResult<StateCommit> {
        let mut observed = match &mutation {
            StateMutation::Set(value)
            | StateMutation::Append(value)
            | StateMutation::CompareSet { value, .. }
            | StateMutation::Merge { value, .. } => value.taint.clone(),
            StateMutation::Delete | StateMutation::CompareDelete { .. } => TaintSet::pristine(),
        };
        let result = (|| -> StateResult<Option<StateEvent>> {
            // Independent replacement encoding does not need the database write
            // lock. Read-modify-write payloads are prepared inside it below.
            let replacement_bytes = match &mutation {
                StateMutation::Set(value) => Some(encode_envelope(&value.value, &value.taint)?),
                _ => None,
            };
            let txn = self.db.begin_write().map_err(backend_error)?;
            let event = {
                let key = path.to_string();
                let mut table = txn.open_table(STATE_VALUES_TABLE).map_err(backend_error)?;
                // Set is independent replacement. Delete needs only provenance;
                // all other mutations inspect the current lossless value.
                let current = if matches!(&mutation, StateMutation::Set(_) | StateMutation::Delete)
                {
                    None
                } else {
                    let current = table
                        .get(key.as_str())
                        .map_err(backend_error)?
                        .map(|guard| decode_envelope(guard.value()))
                        .transpose()?;
                    if let Some(current) = &current {
                        observed.union(&current.taint);
                    }
                    current
                };
                let prepared = match mutation {
                    StateMutation::Set(value) => PreparedMutation::set(path, value),
                    StateMutation::Append(value) => {
                        let stored = xolotl_state::append_value(
                            path,
                            current.as_ref(),
                            value.value.clone(),
                            value.taint.clone(),
                        )?;
                        PreparedMutation {
                            stored: Some(stored),
                            event: StateEvent::Append {
                                path: path.clone(),
                                item: value.value,
                                taint: observed.clone(),
                            },
                        }
                    }
                    StateMutation::CompareSet {
                        expected,
                        mut value,
                    } => {
                        compare(path, expected, current.as_ref())?;
                        value.taint.union(&observed);
                        PreparedMutation::set(path, value)
                    }
                    StateMutation::Delete => {
                        let Some(previous) = table.get(key.as_str()).map_err(backend_error)? else {
                            return Ok(None);
                        };
                        observed.union(&codec::envelope_taint(previous.value())?);
                        PreparedMutation::delete(path, observed.clone())
                    }
                    StateMutation::CompareDelete { expected } => {
                        compare(path, expected, current.as_ref())?;
                        if current.is_none() {
                            return Ok(None);
                        }
                        PreparedMutation::delete(path, observed.clone())
                    }
                    StateMutation::Merge { value, rule } => {
                        let value = xolotl_state::merge_values(
                            current.map(|stored| stored.value),
                            value.value,
                            rule,
                        )?;
                        PreparedMutation::set(path, TaintedValue::new(value, observed.clone()))
                    }
                };
                if let Some(stored) = prepared.stored {
                    let bytes = match replacement_bytes {
                        Some(bytes) => bytes,
                        None => encode_envelope(&stored.value, &stored.taint)?,
                    };
                    table
                        .insert(key.as_str(), bytes.as_slice())
                        .map_err(backend_error)?;
                } else {
                    table.remove(key.as_str()).map_err(backend_error)?;
                }
                prepared.event
            };
            Self::record_history_in_txn(&txn, &event)?;
            txn.commit().map_err(backend_error)?;
            Ok(Some(event))
        })();
        let event = result.map_err(|failure| failure.with_taint(&observed))?;
        if let Some(event) = event {
            self.notify(event);
        }
        Ok(StateCommit { taint: observed })
    }
}

impl StateWrite for RedbStateBackend {
    type Write<'a> = Ready<StateResult<StateCommit>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        ready(self.commit_mutation(path, mutation))
    }
}
