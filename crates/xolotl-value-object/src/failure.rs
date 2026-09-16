//! Operation failures retain the provenance of data already observed.

use core::fmt;
use xolotl_types::TaintSet;

/// A failed object/value operation and the sources observed before it failed.
///
/// Diagnostics and failure selection depend on these sources even when no
/// complete value or committed reference can be returned. Sources are
/// conservative provenance, never a credential granting access to content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure<E> {
    /// Structured operation error, retaining codec or storage details.
    pub error: E,
    /// Input and adapter sources observed before this error was reported.
    pub taint: TaintSet,
}

impl<E> Failure<E> {
    /// Attach the observed sources to a structured error.
    pub fn new(error: E, taint: TaintSet) -> Self {
        Self { error, taint }
    }
}

impl<E: fmt::Display> fmt::Display for Failure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Failure<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}
