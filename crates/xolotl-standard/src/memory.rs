//! State-authoritative memory composed with embedding, index and ranking ports.
//!
//! Stored records retain the admitted representation and a generation. The
//! in-memory index is a rebuildable projection; no asynchronous rollback can
//! delete a newer record. Recall validates generations before attaching scores
//! to records and repairs observed stale hits before repeating the search.
//! Consolidation admits the entire namespace against record, encoded-record
//! and projected-text limits before writing summaries. Word sets borrow the
//! admitted text and cooperative work yields every 1024 inspected tokens,
//! including within a single comparison. Admission rejection writes nothing;
//! later storage failures do not roll back independently committed summaries.

use crate::error::ObservedFailure;
use crate::index::IndexDriver;
use crate::inference::{EchoBackend, InferenceBackend};
use crate::rank::RankerDriver;
use crate::retrieval::{Embedding, EmbeddingRepresentation, admission::invalid};
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_state::{Backend, StateError, StateFailure, TaintedValue};
use xolotl_types::{
    Failure, FloatBits, MethodId, Outcome, OutputMode, Path, Purity, TaintSet, TaintSource, Value,
    ValueMap, ValueText, ValueView,
};

mod text;
use text::entry_text;
mod entry;
use entry::*;
pub(crate) mod consolidation;
use consolidation::consolidate;
mod projection;
mod recall;
mod scan;

const DEFAULT_NAMESPACE: &str = "general";
const SKILLS_NAMESPACE: &str = "skills";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tier {
    Working,
    Recent,
    LongTerm,
    Archive,
}
impl Tier {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Recent => "recent",
            Self::LongTerm => "long_term",
            Self::Archive => "archive",
        }
    }
}

pub(crate) const MEMORY_METHODS: &[MethodSpec] = &[
    MethodSpec::new(
        "store",
        xolotl_types::MethodAuthority::Perform,
        Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "recall",
        xolotl_types::MethodAuthority::Perform,
        Purity::Pure,
        MethodSpec::UNARY_ASYNC,
    )
    .observes_external(),
    MethodSpec::new(
        "forget",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "commit",
        xolotl_types::MethodAuthority::Perform,
        Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "consolidate",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "rebuild",
        xolotl_types::MethodAuthority::Perform,
        Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    )
    .observes_external(),
];

pub(crate) struct MemoryDriver {
    state: Backend,
    index: Arc<IndexDriver>,
    ranker: Arc<RankerDriver>,
    embedder: Arc<dyn InferenceBackend>,
    repair_attempts: NonZeroUsize,
    consolidation_limits: consolidation::ConsolidationLimits,
}

#[derive(Clone)]
struct IndexedEntry {
    id: String,
    space_id: String,
    generation: ValueText,
}

impl MemoryDriver {
    pub(crate) fn new(state: Backend) -> Self {
        Self {
            state,
            index: Arc::new(IndexDriver::new()),
            ranker: Arc::new(RankerDriver::new()),
            embedder: Arc::new(EchoBackend),
            repair_attempts: crate::retrieval::DEFAULT_REPAIR_ATTEMPTS,
            consolidation_limits: consolidation::ConsolidationLimits::default(),
        }
    }

    pub(crate) fn with_retrieval_stack(
        mut self,
        index: Arc<IndexDriver>,
        ranker: Arc<RankerDriver>,
    ) -> Self {
        self.index = index;
        self.ranker = ranker;
        self
    }

    pub(crate) fn with_embedder(mut self, embedder: Arc<dyn InferenceBackend>) -> Self {
        self.embedder = embedder;
        self
    }

    pub(crate) fn with_repair_attempts(mut self, attempts: NonZeroUsize) -> Self {
        self.repair_attempts = attempts;
        self
    }

    pub(crate) fn with_consolidation_limits(
        mut self,
        limits: consolidation::ConsolidationLimits,
    ) -> Self {
        self.consolidation_limits = limits;
        self
    }

    fn index_space(owner: &str, namespace: &str, embedding_space: &str) -> String {
        format!("memory/{owner}/{namespace}/{embedding_space}")
    }

    async fn embed_for_index(
        &self,
        input: &Value,
        taint: &TaintSet,
    ) -> Result<Embedding, ObservedFailure> {
        if self.embedder.requires_unprotected_input() && taint.has_protected() {
            return Err(ObservedFailure::from(invalid(
                "protected memory cannot be sent to the embedding backend",
            ))
            .with_taint(taint));
        }
        let output = self.embedder.embed(input).await.map_err(|error| {
            ObservedFailure::from(DriverError::Other(format!("memory embed failed: {error}")))
                .with_taint(taint)
        })?;
        Embedding::from_value(output).map_err(|error| {
            ObservedFailure::from(invalid(error))
                .with_taint(&TaintSet::of(TaintSource::ModelOutput))
                .with_taint(taint)
        })
    }

    async fn store_or_commit(
        &self,
        input: &ValueMap,
        tier: Tier,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, ObservedFailure> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        let id = id_from_input(input, &owner, &namespace, ctx)?;
        let path = memory_path(&owner, &namespace, &id)?;
        let metric = optional_string(input, "metric")?;
        let expected_generation = optional_string(input, "expected_generation")?;
        let mut entry = TaintedValue::new(
            build_entry(&owner, &namespace, &id, tier, input, ctx)?,
            ctx.taint.clone(),
        );
        let indexed = self
            .write_indexed_entry(&path, &mut entry, metric, expected_generation, ctx)
            .await?;
        let generation = indexed_entry(&entry.value)?.generation;
        Ok(
            DriverOutput::new(Outcome::Done(store_result(&id, &path, indexed, generation)))
                .with_taint(entry.taint),
        )
    }

    async fn forget_from_input(
        &self,
        input: &ValueMap,
        input_taint: &TaintSet,
    ) -> Result<DriverOutput, ObservedFailure> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        if optional_bool(input, "confirm_all", false)? {
            let mut pages =
                scan::NamespaceScan::new(&self.state, namespace_path(&owner, &namespace)?);
            let mut taint = input_taint.clone();
            let mut count = 0_i64;
            while let Some(page) = pages
                .next()
                .await
                .map_err(|error| state_error(error).with_taint(&taint))?
            {
                taint.union(&page.taint);
                for (path, entry) in page.entries {
                    taint.union(&entry.taint);
                    validate_stored_entry(&path, &owner, &namespace, &entry.value)
                        .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                    let (removed, observed) = self
                        .delete_entry_with_index(&entry, &taint)
                        .await
                        .map_err(|error| error.with_taint(&taint))?;
                    taint.union(&observed);
                    if removed {
                        count = count.saturating_add(1);
                    }
                }
            }
            return Ok(DriverOutput::new(Outcome::Done(Value::integer(count))).with_taint(taint));
        }
        let id = required_segment(input, "id")?;
        let path = memory_path(&owner, &namespace, &id)?;
        let entry = self
            .state
            .read_tainted(&path)
            .await
            .map_err(|error| state_error(error).with_taint(input_taint))?;
        let mut observed = input_taint.clone();
        observed.union(&entry.taint);
        let Some(value) = entry.value else {
            return Ok(DriverOutput::new(Outcome::Done(Value::boolean(false))).with_taint(observed));
        };
        let entry = TaintedValue::new(value, entry.taint);
        validate_stored_entry(&path, &owner, &namespace, &entry.value).map_err(|error| {
            ObservedFailure::from(error)
                .with_taint(&entry.taint)
                .with_taint(input_taint)
        })?;
        let (removed, observed) = self.delete_entry_with_index(&entry, input_taint).await?;
        Ok(DriverOutput::new(Outcome::Done(Value::boolean(removed))).with_taint(observed))
    }

    async fn delete_entry_with_index(
        &self,
        entry: &TaintedValue,
        input_taint: &TaintSet,
    ) -> Result<(bool, TaintSet), ObservedFailure> {
        let mut observed = input_taint.clone().merged(&entry.taint);
        let path = entry_path(&entry.value)
            .map_err(|error| ObservedFailure::from(error).with_taint(&observed))?;
        match self
            .state
            .write_compare_delete_tainted(&path, Some(entry.value.clone()), observed.clone())
            .await
        {
            Ok(commit) => {
                observed.union(&commit.taint);
                let indexed = indexed_entry(&entry.value)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&observed))?;
                self.index
                    .delete_generation(&indexed.space_id, &indexed.id, Some(&indexed.generation))
                    .map_err(|error| ObservedFailure::from(error).with_taint(&observed))?;
                Ok((true, observed))
            }
            Err(StateFailure {
                error: StateError::CasFailed { .. },
                mut taint,
            }) => {
                taint.union(&observed);
                Ok((false, taint))
            }
            Err(error) => Err(state_error(error).with_taint(&observed)),
        }
    }

    async fn consolidate_from_input(
        &self,
        input: &ValueMap,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, ObservedFailure> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        let (entries, observed) = self
            .load_namespace_entries_with_limits(&owner, &namespace, Some(self.consolidation_limits))
            .await
            .map_err(|error| error.with_taint(&ctx.taint))?;
        let mut taint = ctx.taint.clone();
        taint.union(&observed);
        let summaries = consolidate(&entries, &owner, &namespace, ctx, self.consolidation_limits)
            .await
            .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
        let count = summaries.len();
        for (path, mut summary) in summaries {
            summary.taint.union(&taint);
            self.write_indexed_entry(&path, &mut summary, None, None, ctx)
                .await
                .map_err(|error| error.with_taint(&taint))?;
            taint.union(&summary.taint);
        }
        Ok(DriverOutput::new(Outcome::Done(Value::integer(count as i64))).with_taint(taint))
    }

    #[cfg(test)]
    async fn load_namespace_entries(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<(Vec<(Path, TaintedValue)>, TaintSet), ObservedFailure> {
        self.load_namespace_entries_with_limits(owner, namespace, None)
            .await
    }

    async fn load_namespace_entries_with_limits(
        &self,
        owner: &str,
        namespace: &str,
        limits: Option<consolidation::ConsolidationLimits>,
    ) -> Result<(Vec<(Path, TaintedValue)>, TaintSet), ObservedFailure> {
        let mut pages = scan::NamespaceScan::new(&self.state, namespace_path(owner, namespace)?);
        let mut entries = Vec::new();
        let mut taint = TaintSet::pristine();
        let mut remaining = limits.map_or(usize::MAX, |limits| limits.encoded_bytes.get());
        loop {
            let remaining_records =
                limits.map_or(usize::MAX, |limits| limits.records.get() - entries.len());
            let page = if let Some(limits) = limits {
                pages
                    .next_bounded(remaining_records, remaining, limits.encoded_bytes)
                    .await
            } else {
                pages.next().await
            }
            .map_err(|error| {
                if limits.is_some()
                    && matches!(error.error, StateError::RowTooLarge(_))
                    && (remaining_records == 0 || remaining == 0)
                {
                    ObservedFailure::from(invalid(if remaining_records == 0 {
                        "memory consolidation record limit exceeded"
                    } else {
                        "memory consolidation encoded byte limit exceeded"
                    }))
                    .with_taint(&error.taint)
                    .with_taint(&taint)
                } else {
                    state_error(error).with_taint(&taint)
                }
            })?;
            let Some(page) = page else {
                break;
            };
            taint.union(&page.taint);
            for (path, entry) in page.entries {
                taint.union(&entry.taint);
                if let Some(limits) = limits {
                    if entries.len() == limits.records.get() {
                        return Err(ObservedFailure::from(invalid(
                            "memory consolidation record limit exceeded",
                        ))
                        .with_taint(&taint));
                    }
                    let bytes = xolotl_state::host::encoded_size(&entry)
                        .map_err(|error| state_error(error).with_taint(&taint))?;
                    remaining = remaining.checked_sub(bytes).ok_or_else(|| {
                        ObservedFailure::from(invalid(
                            "memory consolidation encoded byte limit exceeded",
                        ))
                        .with_taint(&taint)
                    })?;
                }
                validate_stored_entry(&path, owner, namespace, &entry.value)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                entries.push((path, entry));
            }
        }
        Ok((entries, taint))
    }
}

#[async_trait]
impl Driver for MemoryDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let fields = crate::input::map(input, "memory")?;
        let result = match method.get() {
            0 => self.store_or_commit(&fields, Tier::Working, ctx).await,
            1 => self.recall_from_input(&fields, &ctx.taint).await,
            2 => self.forget_from_input(&fields, &ctx.taint).await,
            3 => {
                self.store_or_commit(&fields, tier_from_input(&fields)?, ctx)
                    .await
            }
            4 => self.consolidate_from_input(&fields, ctx).await,
            5 => {
                let owner = required_segment(&fields, "owner")?;
                let namespace = namespace_from_input(&fields)?;
                self.rebuild_namespace(&owner, &namespace)
                    .await
                    .map_err(|error| error.with_taint(&ctx.taint))
                    .map(|(count, observed)| {
                        let taint = ctx.taint.clone().merged(&observed);
                        DriverOutput::new(Outcome::Done(Value::integer(count))).with_taint(taint)
                    })
            }
            _ => return Err(DriverError::NoSuchMethod(method)),
        };
        match result {
            Ok(output) => Ok(output),
            Err(error) => error.into_output("memory"),
        }
    }
}

fn state_error(failure: StateFailure) -> ObservedFailure {
    ObservedFailure::from(failure)
}

fn repair_exhausted(taint: &TaintSet) -> ObservedFailure {
    ObservedFailure::from(Failure::HandlerError {
        kind: "memory_repair_exhausted".into(),
        message: "memory projection did not stabilize within the configured repair attempts".into(),
    })
    .with_taint(taint)
}
fn internal_ctx(taint: &TaintSet) -> DriverContext {
    DriverContext::new(
        xolotl_types::IdentityRef::ROOT,
        xolotl_types::ProcessId::new(0),
    )
    .with_taint(taint.clone())
}

#[cfg(test)]
mod tests;
