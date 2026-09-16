//! Mutable directories publish immutable entry and provenance pages.
//!
//! Active searches retain only the roots they use. There is no version chain,
//! snapshot registry, or copy of the complete numeric payload on mutation.

use super::lsh::{LshIndex, Signatures};
use super::pages::Pages;
use crate::retrieval::admission::{Family, Vector};
use std::collections::BTreeMap;
use std::sync::Arc;
use xolotl_types::{TaintSet, TaintSource, ValueText};

pub(super) const EXACT_SEARCH_LIMIT: usize = 4096;
const ANN_RELEASE_LIMIT: usize = EXACT_SEARCH_LIMIT / 2;
#[cfg(test)]
pub(super) use super::lsh::{
    CANDIDATE_FLOOR as ANN_CANDIDATE_FLOOR, CANDIDATE_MULTIPLIER as ANN_CANDIDATE_MULTIPLIER,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SearchMode {
    Auto,
    Exact,
}

/// The metric is part of a space's schema, so a query cannot reinterpret stored
/// vectors. Multi-vector aggregation is named explicitly rather than inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Metric {
    Cosine,
    Dot,
    NegativeSquaredEuclidean,
    MeanMaxCosine,
}

impl Metric {
    pub(crate) fn parse(value: Option<&str>, family: Family) -> Result<Self, &'static str> {
        match value {
            None | Some("cosine") if family != Family::Multi => Ok(Self::Cosine),
            Some("dot") if family != Family::Multi => Ok(Self::Dot),
            Some("negative_squared_euclidean") if family != Family::Multi => {
                Ok(Self::NegativeSquaredEuclidean)
            }
            Some("mean_max_cosine") if family == Family::Multi => Ok(Self::MeanMaxCosine),
            _ => Err(
                "metric must explicitly match the representation: cosine, dot, negative_squared_euclidean, or mean_max_cosine",
            ),
        }
    }
}

pub(super) struct Entry {
    pub(super) id: String,
    pub(super) vector: Vector,
    pub(super) taint: TaintSet,
    pub(super) generation: Option<ValueText>,
}

#[derive(Clone)]
pub(super) struct Snapshot {
    pub(super) entries: Pages<Arc<Entry>>,
    pub(super) sources: Pages<TaintSource>,
    pub(super) ann: Option<LshIndex>,
    pub(super) dimensions: usize,
    pub(super) family: Family,
    pub(super) metric: Metric,
}

impl Snapshot {
    pub(super) fn wants_ann(&self) -> bool {
        self.family == Family::Dense
            && self.metric == Metric::Cosine
            && self.entries.len() > EXACT_SEARCH_LIMIT
    }
}

pub(super) struct SpaceIndex {
    pub(super) current: Arc<Snapshot>,
    ids: BTreeMap<String, usize>,
    sources: BTreeMap<TaintSource, SourceCount>,
}

struct SourceCount {
    slot: usize,
    count: usize,
}

impl SpaceIndex {
    pub(super) fn new(dimensions: usize, family: Family, metric: Metric) -> Self {
        Self {
            current: Arc::new(Snapshot {
                entries: Pages::default(),
                sources: Pages::default(),
                ann: None,
                dimensions,
                family,
                metric,
            }),
            ids: BTreeMap::new(),
            sources: BTreeMap::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.current.entries.is_empty()
    }

    pub(super) fn matches(&self, vector: &Vector, metric: Metric) -> bool {
        self.current.dimensions == vector.dimensions()
            && self.current.family == vector.family()
            && self.current.metric == metric
    }

    pub(super) fn entry(&self, id: &str) -> Option<&Arc<Entry>> {
        self.ids
            .get(id)
            .and_then(|slot| self.current.entries.get(*slot))
    }

    pub(super) fn upsert(
        &mut self,
        entry: Entry,
        signature: Option<Signatures>,
    ) -> Result<(), &'static str> {
        if self.current.ann.is_some() && signature.is_none() {
            return Err("ANN signature must be prepared outside the space lock");
        }
        let slot = self.ids.get(&entry.id).copied();
        let old = slot
            .and_then(|slot| self.current.entries.get(slot))
            .cloned();
        if let Some(old) = &old {
            self.remove_sources(&old.taint)?;
        }
        self.add_sources(&entry.taint);
        let current = Arc::make_mut(&mut self.current);
        if let Some(slot) = slot {
            if let (Some(ann), Some(signature)) = (&mut current.ann, signature) {
                ann.replace(slot, signature)?;
            }
            *current
                .entries
                .get_mut(slot)
                .ok_or("index directory refers to a missing entry")? = Arc::new(entry);
        } else {
            let slot = current.entries.len();
            self.ids.insert(entry.id.clone(), slot);
            current.entries.push(Arc::new(entry));
            if let (Some(ann), Some(signature)) = (&mut current.ann, signature) {
                ann.push(signature);
            }
        }
        Ok(())
    }

    pub(super) fn delete(
        &mut self,
        id: &str,
        expected_generation: Option<&str>,
    ) -> Result<bool, &'static str> {
        let Some(&slot) = self.ids.get(id) else {
            return Ok(false);
        };
        let entry = self
            .current
            .entries
            .get(slot)
            .cloned()
            .ok_or("index directory refers to a missing removal")?;
        if expected_generation.is_some_and(|expected| entry.generation.as_deref() != Some(expected))
        {
            return Ok(false);
        }
        self.remove_sources(&entry.taint)?;
        let _: Option<usize> = self.ids.remove(id);
        let current = Arc::make_mut(&mut self.current);
        if let Some(ann) = &mut current.ann {
            ann.swap_remove(slot)?;
        }
        current
            .entries
            .swap_remove(slot)
            .ok_or("index entry disappeared during removal")?;
        if let Some(moved) = current.entries.get(slot) {
            self.ids.insert(moved.id.clone(), slot);
        }
        if current.entries.len() <= ANN_RELEASE_LIMIT {
            current.ann = None;
        }
        if current.entries.is_empty() {
            self.ids = BTreeMap::new();
            self.sources = BTreeMap::new();
        }
        Ok(true)
    }

    fn add_sources(&mut self, taint: &TaintSet) {
        for source in taint.sources() {
            if let Some(count) = self.sources.get_mut(source) {
                count.count += 1;
            } else {
                let sources = &mut Arc::make_mut(&mut self.current).sources;
                self.sources.insert(
                    source.clone(),
                    SourceCount {
                        slot: sources.len(),
                        count: 1,
                    },
                );
                sources.push(source.clone());
            }
        }
    }

    fn remove_sources(&mut self, taint: &TaintSet) -> Result<(), &'static str> {
        for source in taint.sources() {
            let count = self
                .sources
                .get_mut(source)
                .ok_or("index source reference count is missing")?;
            count.count -= 1;
            if count.count != 0 {
                continue;
            }
            let slot = count.slot;
            let _removed = self.sources.remove(source);
            let sources = &mut Arc::make_mut(&mut self.current).sources;
            sources
                .swap_remove(slot)
                .ok_or("index source slot is missing")?;
            if let Some(moved) = sources.get(slot) {
                self.sources
                    .get_mut(moved)
                    .ok_or("index source tail is missing")?
                    .slot = slot;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
