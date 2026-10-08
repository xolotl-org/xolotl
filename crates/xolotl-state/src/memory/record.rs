use super::InMemoryOptions;
use crate::{StateError, StateObservation, StateResult, TaintedValue};
use xolotl_types::{Path, TaintSet, Value};

pub(super) enum CurrentRecord {
    Live(TaintedValue),
    Absent {
        taint: TaintSet,
        encoded_bytes: usize,
    },
}

impl CurrentRecord {
    pub(super) fn absent(path: &Path, taint: TaintSet) -> StateResult<Option<Self>> {
        if taint.is_pristine() {
            return Ok(None);
        }
        let observation = StateObservation { value: None, taint };
        let encoded_bytes = crate::host::encoded_size(&observation)
            .and_then(|bytes| record_size(path, bytes))
            .map_err(|failure| failure.with_taint(&observation.taint))?;
        Ok(Some(Self::Absent {
            taint: observation.taint,
            encoded_bytes,
        }))
    }

    pub(super) fn value(&self) -> Option<&Value> {
        match self {
            Self::Live(value) => Some(&value.value),
            Self::Absent { .. } => None,
        }
    }

    pub(super) fn taint(&self) -> &TaintSet {
        match self {
            Self::Live(value) => &value.taint,
            Self::Absent { taint, .. } => taint,
        }
    }

    pub(super) fn live(&self) -> Option<&TaintedValue> {
        match self {
            Self::Live(value) => Some(value),
            Self::Absent { .. } => None,
        }
    }

    pub(super) fn observation(&self) -> StateObservation {
        StateObservation {
            value: self.value().cloned(),
            taint: self.taint().clone(),
        }
    }

    pub(super) fn encoded_bytes(&self, path: &Path) -> StateResult<usize> {
        match self {
            Self::Live(value) => crate::host::encoded_size(value)
                .and_then(|bytes| record_size(path, bytes))
                .map_err(|failure| failure.with_taint(&value.taint)),
            Self::Absent { encoded_bytes, .. } => Ok(*encoded_bytes),
        }
    }

    fn absence_charge(&self) -> AbsenceUsage {
        match self {
            Self::Live(_) => AbsenceUsage::default(),
            Self::Absent { encoded_bytes, .. } => AbsenceUsage {
                records: 1,
                encoded_bytes: *encoded_bytes,
            },
        }
    }
}

pub(super) fn provenance_size(path: &Path, taint: &TaintSet) -> StateResult<usize> {
    record_size(path, crate::host::encoded_size(taint)?)
}

fn record_size(path: &Path, bytes: usize) -> StateResult<usize> {
    path.canonical_len()
        .and_then(|key_bytes| bytes.checked_add(key_bytes))
        .ok_or_else(|| StateError::Backend("state record size overflow".into()).into())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct AbsenceUsage {
    pub(super) records: usize,
    pub(super) encoded_bytes: usize,
}

impl AbsenceUsage {
    pub(super) fn replacing(
        self,
        before: Option<&CurrentRecord>,
        after: Option<&CurrentRecord>,
        options: &InMemoryOptions,
    ) -> StateResult<Self> {
        let before = before.map_or_else(Self::default, CurrentRecord::absence_charge);
        let after = after.map_or_else(Self::default, CurrentRecord::absence_charge);
        let records = self
            .records
            .checked_sub(before.records)
            .and_then(|records| records.checked_add(after.records));
        let encoded_bytes = self
            .encoded_bytes
            .checked_sub(before.encoded_bytes)
            .and_then(|bytes| bytes.checked_add(after.encoded_bytes));
        let next = records
            .zip(encoded_bytes)
            .map(|(records, encoded_bytes)| Self {
                records,
                encoded_bytes,
            })
            .ok_or_else(|| StateError::Backend("state absence accounting overflow".into()))?;
        if options
            .absence_limits
            .records
            .is_some_and(|limit| next.records > limit && next.records > self.records)
            || options.absence_limits.encoded_bytes.is_some_and(|limit| {
                next.encoded_bytes > limit && next.encoded_bytes > self.encoded_bytes
            })
        {
            return Err(StateError::Backend("state absence capacity exhausted".into()).into());
        }
        Ok(next)
    }
}
