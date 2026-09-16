use crate::{StateResult, TaintedValue};
use core::future::Future;
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
    /// Remove the value.
    Delete,
    /// Compare the value only, then remove it in the same atomic commit.
    CompareDelete {
        /// `None` matches absence and succeeds without a mutation or notification;
        /// `Some(Value::null())` matches a stored null. Provenance is not compared.
        expected: Option<Value>,
    },
    /// Merge data and union existing and incoming provenance.
    Merge {
        /// Incoming data and provenance participating in the merge.
        value: TaintedValue,
        /// Merge behavior applied inside the same atomic path commit.
        rule: MergeRule,
    },
}

/// Atomic writes independent of read and query capabilities.
pub trait StateWrite {
    /// Backend-owned write request.
    type Write<'a>: Future<Output = StateResult<StateCommit>>
    where
        Self: 'a;

    /// Complete only after the mutation is visible; publish notifications after
    /// commit. Return all observed sources on both success and failure.
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a>;
}

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
        self.mutate(path, StateMutation::Delete)
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
        self.mutate(path, StateMutation::CompareDelete { expected })
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
