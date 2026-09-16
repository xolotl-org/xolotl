//! State-authoritative memory composed with embedding, index and ranking ports.
//!
//! Stored records retain the admitted representation and a generation. The
//! in-memory index is a rebuildable projection; no asynchronous rollback can
//! delete a newer record. Recall validates generations before attaching scores
//! to records and repairs observed stale hits before repeating the search.

use crate::error::ObservedFailure;
use crate::index::IndexDriver;
use crate::inference::{EchoBackend, InferenceBackend};
use crate::rank::RankerDriver;
use crate::retrieval::{Embedding, EmbeddingRepresentation, admission::invalid};
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_state::{Backend, StateError, StateFailure, TaintedValue};
use xolotl_types::{
    FloatBits, MethodId, Outcome, OutputMode, Path, Purity, TaintSet, TaintSource, Value, ValueMap,
    ValueText, ValueView,
};

mod text;
use text::entry_text;
mod entry;
use entry::*;
mod consolidation;
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
    MethodSpec::new("store", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("recall", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("forget", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("commit", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("consolidate", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("rebuild", Purity::Idempotent, MethodSpec::UNARY_ASYNC).observes_external(),
];

pub(crate) struct MemoryDriver {
    state: Backend,
    index: Arc<IndexDriver>,
    ranker: Arc<RankerDriver>,
    embedder: Arc<dyn InferenceBackend>,
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

    async fn forget_from_input(&self, input: &ValueMap) -> Result<DriverOutput, ObservedFailure> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        if optional_bool(input, "confirm_all", false)? {
            let mut pages =
                scan::NamespaceScan::new(&self.state, namespace_path(&owner, &namespace)?);
            let mut taint = TaintSet::pristine();
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
                        .delete_entry_with_index(&entry)
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
        let Some(entry) = self.state.read_tainted(&path).await.map_err(state_error)? else {
            return Ok(DriverOutput::new(Outcome::Done(Value::boolean(false))));
        };
        validate_stored_entry(&path, &owner, &namespace, &entry.value)
            .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
        let (removed, observed) = self.delete_entry_with_index(&entry).await?;
        Ok(DriverOutput::new(Outcome::Done(Value::boolean(removed))).with_taint(observed))
    }

    async fn delete_entry_with_index(
        &self,
        entry: &TaintedValue,
    ) -> Result<(bool, TaintSet), ObservedFailure> {
        let path = entry_path(&entry.value)
            .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
        match self
            .state
            .write_compare_delete(&path, Some(entry.value.clone()))
            .await
        {
            Ok(commit) => {
                let indexed = indexed_entry(&entry.value)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
                self.index
                    .delete_generation(&indexed.space_id, &indexed.id, Some(&indexed.generation))
                    .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
                Ok((true, entry.taint.clone().merged(&commit.taint)))
            }
            Err(StateFailure {
                error: StateError::CasFailed { .. },
                mut taint,
            }) => {
                taint.union(&entry.taint);
                Ok((false, taint))
            }
            Err(error) => Err(state_error(error).with_taint(&entry.taint)),
        }
    }

    async fn consolidate_from_input(
        &self,
        input: &ValueMap,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, ObservedFailure> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        let (entries, observed) = self.load_namespace_entries(&owner, &namespace).await?;
        let mut taint = ctx.taint.clone();
        taint.union(&observed);
        let summaries = consolidate(&entries, &owner, &namespace, ctx)
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

    async fn load_namespace_entries(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<(Vec<(Path, TaintedValue)>, TaintSet), ObservedFailure> {
        let mut pages = scan::NamespaceScan::new(&self.state, namespace_path(owner, namespace)?);
        let mut entries = Vec::new();
        let mut taint = TaintSet::pristine();
        while let Some(page) = pages
            .next()
            .await
            .map_err(|error| state_error(error).with_taint(&taint))?
        {
            taint.union(&page.taint);
            for (path, entry) in page.entries {
                taint.union(&entry.taint);
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
            2 => self.forget_from_input(&fields).await,
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
                    .map(|(count, taint)| {
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
    ObservedFailure {
        error: DriverError::Other(format!("memory state operation failed: {}", failure.error)),
        taint: failure.taint,
    }
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
