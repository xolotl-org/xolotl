//! A value and its provenance travel together across execution and I/O ports.

use super::TaintSet;
use crate::Value;
use serde::{Deserialize, Serialize};

/// A losslessly encoded value together with its provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaintedValue {
    /// Data carried across the boundary.
    #[serde(with = "crate::tagged_value")]
    pub value: Value,
    /// Provenance associated with the data.
    pub taint: TaintSet,
}

impl TaintedValue {
    /// Wrap an author-trusted value without other provenance.
    pub fn pristine(value: Value) -> Self {
        Self::new(value, TaintSet::pristine())
    }

    /// Preserve an explicit provenance set alongside a value.
    pub fn new(value: Value, taint: TaintSet) -> Self {
        Self { value, taint }
    }
}
