//! Model output delivery with per-chunk provenance and retry visibility.

use std::sync::atomic::{AtomicBool, Ordering};
use xolotl_kernel::DriverContext;
use xolotl_types::{TaintSet, TaintSource, TaintedValue, Value};

/// An operation-owned model output edge. Awaiting `emit` propagates
/// backpressure to the provider request; dropping it never spawns work.
pub struct InferenceStream<'a> {
    context: &'a DriverContext,
    emitted: AtomicBool,
}

impl<'a> InferenceStream<'a> {
    pub(crate) fn new(context: &'a DriverContext) -> Self {
        Self {
            context,
            emitted: AtomicBool::new(false),
        }
    }

    /// Emit model output with the originating operation's input provenance.
    pub async fn emit(&self, value: Value) -> Result<(), String> {
        self.emit_tainted(TaintedValue::pristine(value)).await
    }

    /// Preserve additional provider-assigned lineage on this chunk.
    pub async fn emit_tainted(&self, mut value: TaintedValue) -> Result<(), String> {
        value.taint.union(&TaintSet::of(TaintSource::ModelOutput));
        self.context
            .emit_tainted(value)
            .await
            .map_err(|error| error.to_string())?;
        self.emitted.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn has_output(&self) -> bool {
        self.emitted.load(Ordering::Acquire)
    }
}
