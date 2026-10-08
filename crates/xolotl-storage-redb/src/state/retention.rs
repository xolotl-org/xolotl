//! One bounded transaction folds old history into exact-path baselines.

use super::mutation::{RedbWriteFuture, WriteOwner};
use super::*;
use crate::schema::{
    HISTORY_FLOOR_MILLIS, STATE_HISTORY_BASELINES_TABLE, STATE_HISTORY_TIME_INDEX_TABLE,
};
use redb::{ReadableTable, ReadableTableMetadata};
use std::collections::BTreeMap;
use xolotl_state::{StateHistoryRetention, StateHistoryTrim, StateHistoryTrimLimits};

impl WriteOwner {
    fn trim_history_before(
        &self,
        floor: i64,
        limits: StateHistoryTrimLimits,
    ) -> StateResult<StateHistoryTrim> {
        if self.history == RedbHistory::CurrentOnly {
            return Err(StateError::MissingCapability("history_retention").into());
        }
        let txn = self.db.begin_write().map_err(backend_error)?;
        let previous_floor;
        let last_history_millis;
        {
            let meta = txn.open_table(STATE_META_TABLE).map_err(backend_error)?;
            previous_floor = meta
                .get(HISTORY_FLOOR_MILLIS)
                .map_err(backend_error)?
                .ok_or_else(|| backend_error("state history floor metadata missing"))?
                .value();
            last_history_millis = meta
                .get(LAST_HISTORY_MILLIS)
                .map_err(backend_error)?
                .ok_or_else(|| backend_error("state history clock metadata missing"))?
                .value();
            if floor <= 0 || floor == i64::MAX || floor < previous_floor {
                return Err(StateError::InvalidQuery(
                    "history trim floor must advance and leave room for later writes".into(),
                )
                .into());
            }
        }
        if floor == previous_floor {
            return Ok(StateHistoryTrim {
                retained_from_millis: floor,
                removed_events: 0,
            });
        }

        #[cfg(feature = "federation")]
        crate::federation_projection::check_state_history_retirement(&txn, floor)
            .map_err(backend_error)?;
        #[cfg(not(feature = "federation"))]
        if !txn
            .open_table(crate::schema::FEDERATION_STATE_PROJECTION_TABLE)
            .map_err(backend_error)?
            .is_empty()
            .map_err(backend_error)?
        {
            return Err(StateError::MissingCapability("federation_history_retention").into());
        }

        let mut observed = TaintSet::pristine();
        // The transaction can fail at any later read, decode, update, or
        // commit step. Preserve every source inspected before that failure.
        let result = (|| -> StateResult<StateHistoryTrim> {
            let mut baselines = txn
                .open_table(STATE_HISTORY_BASELINES_TABLE)
                .map_err(backend_error)?;
            let mut history = txn.open_table(STATE_HISTORY_TABLE).map_err(backend_error)?;
            let mut time_index = txn
                .open_table(STATE_HISTORY_TIME_INDEX_TABLE)
                .map_err(backend_error)?;
            if history.len().map_err(backend_error)? != time_index.len().map_err(backend_error)? {
                return Err(backend_error(
                    "state history time index count does not match history",
                ));
            }
            let mut removed_events = 0usize;
            let mut input_bytes = 0usize;
            let mut existing_baseline_bytes = 0usize;
            let mut staged: BTreeMap<Path, xolotl_state::StateObservation> = BTreeMap::new();
            let upper = history_time_bound(floor);
            let rows = time_index
                .extract_from_if(..upper.as_slice(), |_, _| true)
                .map_err(backend_error)?;
            for row in rows {
                let (time_key, _) = row.map_err(backend_error)?;
                removed_events = removed_events
                    .checked_add(1)
                    .ok_or_else(|| trim_limit(&observed, false))?;
                if removed_events > limits.events.get() {
                    return Err(trim_limit(&observed, false));
                }
                let primary_key = time_key
                    .value()
                    .get(8..)
                    .filter(|key| !key.is_empty())
                    .ok_or_else(|| backend_error("state history time index key is malformed"))?;
                let (path, at_millis) = history_key_parts(primary_key)?;
                if history_time_bound(at_millis) != time_key.value()[..8] {
                    return Err(backend_error(
                        "state history time index key disagrees with history",
                    ));
                }
                let bytes = history
                    .remove(primary_key)
                    .map_err(backend_error)?
                    .ok_or_else(|| backend_error("state history time index has no event"))?;
                input_bytes = input_bytes
                    .checked_add(primary_key.len())
                    .and_then(|count| count.checked_add(time_key.value().len()))
                    .and_then(|count| count.checked_add(bytes.value().len()))
                    .ok_or_else(|| trim_limit(&observed, false))?;
                if input_bytes.saturating_add(existing_baseline_bytes) > limits.encoded_bytes.get()
                {
                    return Err(trim_limit(&observed, false));
                }
                observed.union(&codec::history_taint(bytes.value())?);
                let entry = read::decode_indexed_entry(bytes.value(), &path, at_millis)?;
                if !staged.contains_key(&path) {
                    let key = path.to_string();
                    let initial = if matches!(entry.event, StateEvent::Set { .. }) {
                        None
                    } else {
                        baselines
                            .get(key.as_str())
                            .map_err(backend_error)?
                            .map(|guard| {
                                existing_baseline_bytes = existing_baseline_bytes
                                    .checked_add(key.len())
                                    .and_then(|count| count.checked_add(guard.value().len()))
                                    .ok_or(StateError::HistoryTrimLimit {
                                        provenance_observed: false,
                                    })?;
                                if input_bytes.saturating_add(existing_baseline_bytes)
                                    > limits.encoded_bytes.get()
                                {
                                    return Err(StateError::HistoryTrimLimit {
                                        provenance_observed: false,
                                    }
                                    .into());
                                }
                                codec::decode_observation(guard.value())
                            })
                            .transpose()?
                    };
                    if let Some(value) = &initial {
                        observed.union(&value.taint);
                    }
                    staged.insert(path.clone(), initial.unwrap_or_default());
                }
                let current = staged
                    .get_mut(&path)
                    .ok_or_else(|| backend_error("staged history path missing"))?;
                xolotl_state::apply_history_event(current, &entry.event)?;
            }
            let mut output_baseline_bytes = 0usize;
            for (path, value) in staged {
                let key = path.to_string();
                if value.value.is_some() || !value.taint.is_pristine() {
                    let bytes = codec::encode_observation(&value)?;
                    output_baseline_bytes = output_baseline_bytes
                        .checked_add(key.len())
                        .and_then(|count| count.checked_add(bytes.len()))
                        .ok_or_else(|| trim_limit(&observed, true))?;
                    if input_bytes.saturating_add(output_baseline_bytes)
                        > limits.encoded_bytes.get()
                    {
                        return Err(trim_limit(&observed, true));
                    }
                    baselines
                        .insert(key.as_str(), bytes.as_slice())
                        .map_err(backend_error)?;
                } else {
                    baselines.remove(key.as_str()).map_err(backend_error)?;
                }
            }
            drop(time_index);
            drop(history);
            drop(baselines);
            {
                let mut meta = txn.open_table(STATE_META_TABLE).map_err(backend_error)?;
                meta.insert(HISTORY_FLOOR_MILLIS, floor)
                    .map_err(backend_error)?;
                meta.insert(LAST_HISTORY_MILLIS, last_history_millis.max(floor - 1))
                    .map_err(backend_error)?;
            }
            txn.commit().map_err(commit_error)?;
            Ok(StateHistoryTrim {
                retained_from_millis: floor,
                removed_events: removed_events as u64,
            })
        })();
        result.map_err(|failure| failure.with_taint(&observed))
    }
}

fn trim_limit(observed: &TaintSet, provenance_observed: bool) -> StateFailure {
    StateFailure::new(
        StateError::HistoryTrimLimit {
            provenance_observed,
        },
        observed.clone(),
    )
}

impl StateHistoryRetention for RedbStateBackend {
    type Floor<'a> = read::RedbReadFuture<'a, (), (), i64>;
    type Trim<'a> = RedbWriteFuture<
        'a,
        (i64, StateHistoryTrimLimits),
        (i64, StateHistoryTrimLimits),
        StateHistoryTrim,
    >;

    fn retained_from(&self) -> Self::Floor<'_> {
        read::retained_from(self)
    }

    fn trim_before(&self, floor: i64, limits: StateHistoryTrimLimits) -> Self::Trim<'_> {
        RedbWriteFuture::new(
            self,
            (floor, limits),
            std::convert::identity,
            |owner, (floor, limits)| owner.trim_history_before(floor, limits),
            TaintSet::pristine(),
        )
    }
}
