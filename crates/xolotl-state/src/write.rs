use crate::{StateError, StateEvent, StateResult, TaintedValue};
use alloc::{boxed::Box, string::ToString};
use core::{future::Future, num::NonZeroUsize};
use xolotl_types::{MergeRule, Path, TaintSet, Value};

/// A committed mutation and every source observed while deciding its outcome.
/// This includes successful comparisons and no-op conditional deletions. It is
/// independent of the provenance stored by a replacement mutation.
#[derive(Clone, Debug, Default)]
pub struct StateCommit {
    /// Sources participating in the atomic mutation's observation.
    pub taint: TaintSet,
}

/// One atomic path mutation. Comparisons and merges execute within the backend commit.
pub enum StateMutation {
    /// Replace the value and provenance.
    Set(TaintedValue),
    /// Append an item and union its provenance with the sequence.
    Append(TaintedValue),
    /// Compare the value only, then replace the value and union provenance.
    CompareSet {
        /// Value required inside the atomic commit. `None` matches absence;
        /// `Some(Value::null())` matches a stored null. Provenance is not compared.
        expected: Option<Value>,
        /// Replacement value and incoming provenance. Successful comparisons
        /// atomically retain the current value's sources in the replacement.
        value: TaintedValue,
    },
    /// Remove the value, retaining deletion input and control provenance.
    Delete(TaintSet),
    /// Compare the value only, then remove it in the same atomic commit.
    CompareDelete {
        /// `None` matches absence and succeeds without a mutation or notification;
        /// `Some(Value::null())` matches a stored null. Provenance is not compared.
        expected: Option<Value>,
        /// Sources of the comparison and deletion input or control decision.
        taint: TaintSet,
    },
    /// Merge data and union existing and incoming provenance.
    Merge {
        /// Incoming data and provenance participating in the merge.
        value: TaintedValue,
        /// Merge behavior applied inside the same atomic path commit.
        rule: MergeRule,
    },
}

impl StateMutation {
    /// Known input and control sources, before observing any current record.
    pub fn input_taint(&self) -> &TaintSet {
        match self {
            Self::Set(value)
            | Self::Append(value)
            | Self::CompareSet { value, .. }
            | Self::Merge { value, .. } => &value.taint,
            Self::Delete(taint) | Self::CompareDelete { taint, .. } => taint,
        }
    }

    /// Prepare an Append from same-domain shape metadata and observed sources.
    ///
    /// None means absence, Some(true) a List, and Some(false) a non-List.
    /// This is the same event preparation used by resident mutations; storage
    /// backends need not materialize a List just to validate an incremental call.
    pub fn prepare_append_event(
        path: &Path,
        value: TaintedValue,
        current_is_list: Option<bool>,
        mut observed: TaintSet,
    ) -> StateResult<StateEvent> {
        observed.union(&value.taint);
        if current_is_list == Some(false) {
            return Err(crate::StateFailure::new(
                StateError::Backend(alloc::format!("append on non-list at {path}")),
                observed,
            ));
        }
        Ok(StateEvent::Append {
            path: path.clone(),
            item: value.value,
            taint: observed,
        })
    }

    /// Prepare an event against a borrowed value and already observed sources
    /// inside the backend's commit domain, retaining known mutation inputs.
    /// Absence may carry sources independently of a value. A backend can share
    /// its accumulated sources without constructing a second equivalent set.
    /// Encoding, capacity checks, current-record construction and publication
    /// remain backend responsibilities. Append stays an incremental event.
    pub fn prepare_event(
        self,
        path: &Path,
        current: Option<&Value>,
        mut observed: TaintSet,
    ) -> StateResult<Option<StateEvent>> {
        observed.union(self.input_taint());
        let result = (|| {
            let event = match self {
                Self::Set(value) => StateEvent::Set {
                    path: path.clone(),
                    value: value.value,
                    taint: value.taint,
                },
                Self::Append(value) => Self::prepare_append_event(
                    path,
                    value,
                    current.map(|value| value.as_list().is_some()),
                    observed.clone(),
                )?,
                Self::CompareSet { expected, value } => {
                    compare_observation(path, expected, current)?;
                    StateEvent::Set {
                        path: path.clone(),
                        value: value.value,
                        taint: observed.clone(),
                    }
                }
                Self::Delete(_) => {
                    return Ok(current.map(|_| StateEvent::Delete {
                        path: path.clone(),
                        taint: observed.clone(),
                    }));
                }
                Self::CompareDelete { expected, .. } => {
                    compare_observation(path, expected, current)?;
                    return Ok(current.map(|_| StateEvent::Delete {
                        path: path.clone(),
                        taint: observed.clone(),
                    }));
                }
                Self::Merge { value, rule } => StateEvent::Set {
                    path: path.clone(),
                    value: crate::merge_values(current.cloned(), value.value, rule)?,
                    taint: observed.clone(),
                },
            };
            Ok(Some(event))
        })();
        result.map_err(|failure: crate::StateFailure| failure.with_taint(&observed))
    }
}

fn compare_observation(
    path: &Path,
    expected: Option<Value>,
    current: Option<&Value>,
) -> StateResult<()> {
    if current == expected.as_ref() {
        return Ok(());
    }
    Err(StateError::CasFailed {
        path: path.to_string(),
        expected: expected.map(Box::new),
        actual: current.cloned().map(Box::new),
    }
    .into())
}

#[cfg(test)]
mod tests;

/// Atomic writes independent of read and query capabilities.
pub trait StateWrite {
    /// Backend-owned write request.
    type Write<'a>: Future<Output = StateResult<StateCommit>>
    where
        Self: 'a;

    /// Complete only after the mutation is visible; publish notifications after
    /// commit. Return all observed sources on both success and failure. A
    /// backend may report [`crate::StateError::CommitUncertain`] when a commit
    /// acknowledgement is lost; callers must reconcile before repeating a
    /// non-idempotent mutation.
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a>;
}

/// Atomic conditional writes that bound the current record observed inside the
/// same commit. This capability is independent of unrestricted [`StateWrite`]
/// and bounded point reads; a preceding bounded read cannot limit a concurrent
/// replacement seen by a later comparison.
pub trait StateBoundedWrite {
    /// Backend-owned conditional write request.
    type BoundedWrite<'a>: Future<Output = StateResult<StateCommit>>
    where
        Self: 'a;

    /// Compare the current value and replace it, unioning current and incoming
    /// provenance. Reject an over-budget current record before copying or
    /// decoding it. Absence has no encoded row to measure.
    ///
    /// The byte limit uses the backend's lossless encoding, including the key
    /// and provenance. It bounds only the observed current record, not the
    /// incoming replacement, retained history, or resident heap. On a
    /// size-only rejection, `PointTooLarge` reports that
    /// provenance was not observed and the actual value is unavailable. A
    /// comparison within budget retains the ordinary `CasFailed` actual value
    /// and the sources observed inside this commit.
    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a>;

    /// Compare and delete the current value with the same observation bound.
    /// `None` matches absence and succeeds without a mutation or notification.
    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a>;
}

/// Pristine-data constructors for bounded conditional writes.
pub trait StateBoundedWriteExt: StateBoundedWrite {
    /// Atomically compare and replace with a pristine incoming value.
    fn write_cas_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: Value,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        self.compare_set_bounded(
            path,
            expected,
            TaintedValue::pristine(value),
            max_current_encoded_bytes,
        )
    }

    /// Atomically compare and delete within the current-record byte budget.
    fn write_compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        self.write_compare_delete_tainted_bounded(
            path,
            expected,
            TaintSet::pristine(),
            max_current_encoded_bytes,
        )
    }

    /// Compare and delete while retaining input and control provenance.
    fn write_compare_delete_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        self.compare_delete_bounded(path, expected, taint, max_current_encoded_bytes)
    }
}
impl<T: StateBoundedWrite + ?Sized> StateBoundedWriteExt for T {}

/// Typed mutation constructors. Every helper delegates to the same commit path.
pub trait StateWriteExt: StateWrite {
    /// Replace a path's value and provenance with the supplied pair.
    fn write_set_tainted<'a>(
        &'a self,
        path: &'a Path,
        value: Value,
        taint: TaintSet,
    ) -> Self::Write<'a> {
        self.mutate(path, StateMutation::Set(TaintedValue::new(value, taint)))
    }
    /// Replace a path's value and mark its stored provenance pristine.
    fn write_set<'a>(&'a self, path: &'a Path, value: Value) -> Self::Write<'a> {
        self.mutate(path, StateMutation::Set(TaintedValue::pristine(value)))
    }
    /// Append an item, unioning its provenance with the existing sequence.
    /// A missing path starts a list; an existing non-list is rejected.
    fn write_append_tainted<'a>(
        &'a self,
        path: &'a Path,
        item: Value,
        taint: TaintSet,
    ) -> Self::Write<'a> {
        self.mutate(path, StateMutation::Append(TaintedValue::new(item, taint)))
    }
    /// Append a pristine item while retaining existing sequence provenance.
    fn write_append<'a>(&'a self, path: &'a Path, item: Value) -> Self::Write<'a> {
        self.mutate(path, StateMutation::Append(TaintedValue::pristine(item)))
    }
    /// Atomically compare the stored value and replace it, retaining the union
    /// of current and incoming provenance even when only labels changed.
    /// `expected: None` matches absence, not a stored null; a mismatch returns
    /// [`crate::StateError::CasFailed`] without changing the path.
    fn write_cas_tainted<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: Value,
        taint: TaintSet,
    ) -> Self::Write<'a> {
        self.mutate(
            path,
            StateMutation::CompareSet {
                expected,
                value: TaintedValue::new(value, taint),
            },
        )
    }
    /// Atomically compare and replace a value, retaining its current provenance.
    /// `None` matches absence; `Some(Value::null())` matches a stored null.
    fn write_cas<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: Value,
    ) -> Self::Write<'a> {
        self.mutate(
            path,
            StateMutation::CompareSet {
                expected,
                value: TaintedValue::pristine(value),
            },
        )
    }
    /// Remove a path's current value; deleting an absent path succeeds unchanged.
    fn write_delete<'a>(&'a self, path: &'a Path) -> Self::Write<'a> {
        self.write_delete_tainted(path, TaintSet::pristine())
    }
    /// Remove a value while retaining deletion input and control provenance.
    fn write_delete_tainted<'a>(&'a self, path: &'a Path, taint: TaintSet) -> Self::Write<'a> {
        self.mutate(path, StateMutation::Delete(taint))
    }
    /// Atomically remove a path only when its current value matches `expected`.
    /// `None` matches absence and succeeds unchanged; `Some(Value::null())` matches
    /// a stored null. A mismatch returns [`crate::StateError::CasFailed`] without
    /// changing data, provenance, history, or notifications.
    fn write_compare_delete<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
    ) -> Self::Write<'a> {
        self.write_compare_delete_tainted(path, expected, TaintSet::pristine())
    }
    /// Compare and remove a value with explicit input and control provenance.
    fn write_compare_delete_tainted<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
    ) -> Self::Write<'a> {
        self.mutate(path, StateMutation::CompareDelete { expected, taint })
    }
    /// Merge pristine incoming data while retaining existing provenance.
    fn write_merge<'a>(&'a self, path: &'a Path, value: Value, rule: MergeRule) -> Self::Write<'a> {
        self.mutate(
            path,
            StateMutation::Merge {
                value: TaintedValue::pristine(value),
                rule,
            },
        )
    }
    /// Atomically merge the incoming data and union its provenance with existing data.
    fn write_merge_tainted<'a>(
        &'a self,
        path: &'a Path,
        value: TaintedValue,
        rule: MergeRule,
    ) -> Self::Write<'a> {
        self.mutate(path, StateMutation::Merge { value, rule })
    }
}
impl<T: StateWrite + ?Sized> StateWriteExt for T {}

/// Optional durable flush or host maintenance barrier.
pub trait StateFlush {
    /// Backend-owned state for its flush or maintenance barrier.
    type Flush<'a>: Future<Output = StateResult<()>>
    where
        Self: 'a;
    /// Complete the backend's declared flush or maintenance work. Persistence
    /// guarantees belong to the implementation; an in-memory backend need not
    /// make volatile data durable.
    fn flush(&self) -> Self::Flush<'_>;
}
