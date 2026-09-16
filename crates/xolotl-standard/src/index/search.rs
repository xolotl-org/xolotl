//! Cooperative scoring over one immutable space view.

use super::storage::{Entry, Metric, SearchMode, Snapshot};
use crate::retrieval::{
    RetrievalConfig,
    admission::{Vector, Work},
};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use xolotl_types::{TaintSet, ValueText};

pub(super) struct Hit {
    pub(super) id: String,
    pub(super) score: f64,
    pub(super) generation: Option<ValueText>,
}

pub(super) struct SearchResult {
    pub(super) hits: Vec<Hit>,
    pub(super) taint: TaintSet,
    #[cfg(test)]
    pub(super) examined: usize,
}

impl Snapshot {
    pub(super) async fn search(
        &self,
        query: &Vector,
        query_taint: &TaintSet,
        k: usize,
        mode: SearchMode,
        config: &RetrievalConfig,
    ) -> SearchResult {
        let mut work = Work::new(config);
        let limit = k.min(self.entries.len());
        let mut top = BinaryHeap::new();
        #[cfg(test)]
        let mut examined = 0;
        if limit != 0 {
            let candidates = if mode == SearchMode::Auto
                && self.wants_ann()
                && let (Some(ann), Some(query)) = (&self.ann, query.dense())
            {
                Some(ann.candidates(query, k, &mut work).await)
            } else {
                None
            };
            let count = candidates.as_ref().map_or(self.entries.len(), Vec::len);
            for position in 0..count {
                let slot = candidates
                    .as_ref()
                    .map_or(position, |slots| slots[position]);
                if let Some(entry) = self.entries.get(slot) {
                    let candidate = Scored {
                        entry,
                        score: score(query, &entry.vector, self.metric, &mut work).await,
                    };
                    #[cfg(test)]
                    {
                        examined += 1;
                    }
                    if top.len() < limit {
                        top.push(candidate);
                    } else if let Some(mut worst) = top.peek_mut()
                        && candidate < *worst
                    {
                        *worst = candidate;
                    }
                }
                work.tick().await;
            }
        }
        let mut hits = Vec::new();
        while let Some(candidate) = top.pop() {
            hits.push(Hit {
                id: candidate.entry.id.clone(),
                score: candidate.score,
                generation: candidate.entry.generation.clone(),
            });
            work.tick().await;
        }
        for left in 0..hits.len() / 2 {
            let right = hits.len() - left - 1;
            hits.swap(left, right);
            work.tick().await;
        }
        // Candidate selection and ordering depend on the whole selected space,
        // even when protected entries miss top-k or no hits are returned.
        let taint = self.observed_sources(query_taint, &mut work).await;
        SearchResult {
            hits,
            taint,
            #[cfg(test)]
            examined,
        }
    }

    pub(super) async fn observed_sources(&self, input: &TaintSet, work: &mut Work) -> TaintSet {
        let mut seen = HashSet::new();
        let mut sources = Vec::new();
        for source in input.sources().iter().chain(self.sources.iter()) {
            if seen.insert(source.clone()) {
                sources.push(source.clone());
            }
            work.tick().await;
        }
        TaintSet::from_recorded_sources(sources)
    }
}

#[derive(Clone, Copy)]
struct Scored<'a> {
    entry: &'a Entry,
    score: f64,
}

impl PartialEq for Scored<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Scored<'_> {}
impl PartialOrd for Scored<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Scored<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .total_cmp(&self.score)
            .then_with(|| self.entry.id.cmp(&other.entry.id))
    }
}

async fn score(query: &Vector, entry: &Vector, metric: Metric, work: &mut Work) -> f64 {
    match (query, entry) {
        (
            Vector::Dense {
                values: query,
                inverse_norm: query_inverse,
            },
            Vector::Dense {
                values: entry,
                inverse_norm: entry_inverse,
            },
        ) => dense(query, *query_inverse, entry, *entry_inverse, metric, work).await,
        (
            Vector::Sparse {
                indices: query_indices,
                values: query,
                inverse_norm: query_inverse,
                ..
            },
            Vector::Sparse {
                indices: entry_indices,
                values: entry,
                inverse_norm: entry_inverse,
                ..
            },
        ) => {
            let mut qi = 0;
            let mut ei = 0;
            let mut sum = 0.0;
            while qi < query_indices.len() || ei < entry_indices.len() {
                let ordering = match (query_indices.get(qi), entry_indices.get(ei)) {
                    (Some(q), Some(e)) => q.cmp(e),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => break,
                };
                let (q, e) = match ordering {
                    Ordering::Less => {
                        let q = query[qi];
                        qi += 1;
                        (q, 0.0)
                    }
                    Ordering::Greater => {
                        let e = entry[ei];
                        ei += 1;
                        (0.0, e)
                    }
                    Ordering::Equal => {
                        let pair = (query[qi], entry[ei]);
                        qi += 1;
                        ei += 1;
                        pair
                    }
                };
                sum += term(q, e, metric);
                work.tick().await;
            }
            finish(sum, *query_inverse, *entry_inverse, metric)
        }
        (
            Vector::Multi {
                dimensions,
                values: query,
                inverse_norms: query_inverse,
            },
            Vector::Multi {
                values: entry,
                inverse_norms: entry_inverse,
                ..
            },
        ) => {
            let mut sum = 0.0;
            for (q, qi) in query.chunks(*dimensions).zip(query_inverse) {
                let mut maximum = f64::NEG_INFINITY;
                for (e, ei) in entry.chunks(*dimensions).zip(entry_inverse) {
                    maximum = maximum.max(dense(q, *qi, e, *ei, Metric::Cosine, work).await);
                    work.tick().await;
                }
                sum += maximum;
            }
            sum / query_inverse.len() as f64
        }
        // Space admission requires equal representation families before search.
        _ => 0.0,
    }
}

async fn dense(
    query: &[f32],
    query_inverse: f64,
    entry: &[f32],
    entry_inverse: f64,
    metric: Metric,
    work: &mut Work,
) -> f64 {
    let mut sum = 0.0;
    for (query, entry) in query.iter().zip(entry) {
        sum += term(*query, *entry, metric);
        work.tick().await;
    }
    finish(sum, query_inverse, entry_inverse, metric)
}

fn term(query: f32, entry: f32, metric: Metric) -> f64 {
    let query = f64::from(query);
    let entry = f64::from(entry);
    if metric == Metric::NegativeSquaredEuclidean {
        let delta = query - entry;
        -(delta * delta)
    } else {
        query * entry
    }
}

fn finish(sum: f64, query_inverse: f64, entry_inverse: f64, metric: Metric) -> f64 {
    let score = if metric == Metric::Cosine {
        (sum * query_inverse * entry_inverse).clamp(-1.0, 1.0)
    } else {
        sum
    };
    if score == 0.0 { 0.0 } else { score }
}
