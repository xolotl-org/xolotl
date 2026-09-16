//! Outcome, provenance and usage returned by one capability invocation.

use alloc::{borrow::Cow, collections::BTreeMap, string::String};

use crate::{ExecutionOutput, Outcome, TaintSet, TaintedFailure, TaintedValue};

/// A named usage unit independent of provider or pricing model.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UsageDimension(Cow<'static, str>);

impl UsageDimension {
    /// Bytes read from a resource.
    pub const BYTES_READ: Self = Self(Cow::Borrowed("bytes_read"));
    /// Bytes written to a resource.
    pub const BYTES_WRITTEN: Self = Self(Cow::Borrowed("bytes_written"));
    /// Measured CPU time in nanoseconds.
    pub const CPU_NANOSECONDS: Self = Self(Cow::Borrowed("cpu_nanoseconds"));
    /// Tokens consumed by a token-based resource.
    pub const INPUT_TOKENS: Self = Self(Cow::Borrowed("input_tokens"));
    /// Tokens produced by a token-based resource.
    pub const OUTPUT_TOKENS: Self = Self(Cow::Borrowed("output_tokens"));

    /// Define a usage dimension understood by the driver and its caller.
    pub fn new(name: impl Into<String>) -> Self {
        Self(Cow::Owned(name.into()))
    }

    /// Stable dimension name used by admission and accounting adapters.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Measured quantities reported by one driver call, without price conversion.
pub type DriverUsage = BTreeMap<UsageDimension, u64>;

/// How an execution boundary obtained its completion, independently of the outcome.
/// A cached child invocation does not make its enclosing program a cached request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CompletionOrigin {
    /// Produced by this attempt, including rejection before driver dispatch.
    #[default]
    CurrentAttempt,
    /// Reused a previous outcome without replaying its historical stream chunks.
    CachedOutcome,
}

/// A driver result and its provenance from the same execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverOutput {
    /// Returned value or domain failure.
    pub outcome: Outcome,
    /// Provenance of the returned value.
    pub taint: TaintSet,
    /// Measured usage, or `None` when the driver does not report it.
    pub usage: Option<DriverUsage>,
    /// Whether this completion was produced now or reused from a previous call.
    pub origin: CompletionOrigin,
}

impl DriverOutput {
    /// Construct an output with pristine provenance and unknown usage.
    pub fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            taint: TaintSet::pristine(),
            usage: None,
            origin: CompletionOrigin::CurrentAttempt,
        }
    }

    /// Attach provenance obtained alongside the returned value.
    pub fn with_taint(mut self, taint: TaintSet) -> Self {
        self.taint = taint;
        self
    }

    /// Attach the measurements reported for this call.
    pub fn with_usage(mut self, usage: DriverUsage) -> Self {
        self.usage = Some(usage);
        self
    }

    /// Mark how this attempt obtained its completion.
    pub fn with_origin(mut self, origin: CompletionOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Deliver this call to a program without losing successful or failed lineage.
    /// Invocation usage and cache origin remain properties of this call; they
    /// do not propagate as metadata of intermediate program values.
    pub fn into_result(self) -> Result<TaintedValue, TaintedFailure> {
        ExecutionOutput::new(self.outcome, self.taint).into_result()
    }
}

impl From<Outcome> for DriverOutput {
    fn from(outcome: Outcome) -> Self {
        Self::new(outcome)
    }
}
