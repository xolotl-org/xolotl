//! Composable retrieval over explicit representations and immutable space views.
//!
//! Registry locks only resolve or retire spaces. Numeric admission, tensor I/O,
//! ANN construction, scoring and result assembly run without a lock guard and
//! yield according to the host's scalar work quantum. Exact search observes one
//! immutable version; optional cosine ANN uses that same version's memberships.

use crate::error::ObservedFailure;
use crate::retrieval::{
    EmbeddingRepresentation, RetrievalConfig,
    admission::{self, Work},
};
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{
    FloatBits, MethodId, Outcome, OutputMode, Purity, TaintSet, Value, ValueMap, ValueText,
    ValueView,
};

mod lsh;
mod pages;
mod search;
mod storage;
use lsh::{LshIndex, Signatures};
use storage::{Entry, Metric, SearchMode, Snapshot, SpaceIndex};

pub(crate) const INDEX_METHODS: &[MethodSpec] = &[
    MethodSpec::new("upsert", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable(),
    MethodSpec::new("search", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

#[derive(Clone, Default)]
pub(crate) struct IndexDriver {
    spaces: Arc<RwLock<BTreeMap<String, Arc<Space>>>>,
    config: RetrievalConfig,
    #[cfg(test)]
    last_search_examined: Arc<AtomicUsize>,
}

struct Space {
    // A retired space stays retired. Holders resolve the registry again instead
    // of resurrecting an old handle after the final entry is deleted.
    state: Mutex<Option<SpaceIndex>>,
    building_ann: AtomicBool,
}

pub(crate) struct PreparedEntry {
    entry: Entry,
    metric: Metric,
    signature: Option<Signatures>,
    observed: Option<Arc<Entry>>,
    conditional: bool,
}

impl PreparedEntry {
    pub(crate) fn taint(&self) -> &TaintSet {
        &self.entry.taint
    }
    pub(crate) fn conditional(mut self) -> Self {
        self.conditional = true;
        self
    }
    pub(crate) fn add_taint(&mut self, taint: &TaintSet) {
        self.entry.taint.union(taint);
    }
}

impl IndexDriver {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_config(mut self, config: RetrievalConfig) -> Self {
        self.config = config;
        self
    }

    pub(crate) async fn prepare(
        &self,
        space: &str,
        id: String,
        representation: EmbeddingRepresentation,
        generation: Option<ValueText>,
        metric: Option<&str>,
        taint: &TaintSet,
    ) -> Result<PreparedEntry, ObservedFailure> {
        let admitted = admission::admit(representation, &self.config, taint).await?;
        let metric = Metric::parse(metric, admitted.vector.family()).map_err(|error| {
            ObservedFailure::from(admission::invalid(error)).with_taint(&admitted.taint)
        })?;
        let resolved = self.spaces.read().get(space).cloned();
        let (snapshot, observed) = resolved
            .as_ref()
            .and_then(|space| {
                space
                    .state
                    .lock()
                    .as_ref()
                    .map(|index| (Some(index.current.clone()), index.entry(&id).cloned()))
            })
            .unwrap_or((None, None));
        let mut work = Work::new(&self.config);
        if let Some(snapshot) = &snapshot
            && (snapshot.dimensions != admitted.vector.dimensions()
                || snapshot.family != admitted.vector.family()
                || snapshot.metric != metric)
        {
            return Err(ObservedFailure {
                error: admission::invalid(
                    "embedding does not match the index space's representation, dimension, or metric",
                ),
                taint: snapshot.observed_sources(&admitted.taint, &mut work).await,
            });
        }
        let signature = if let (Some(ann), Some(vector)) = (
            snapshot.as_ref().and_then(|snapshot| snapshot.ann.as_ref()),
            admitted.vector.dense(),
        ) {
            Some(ann.signature(vector, &mut work).await)
        } else {
            None
        };
        Ok(PreparedEntry {
            entry: Entry {
                id,
                vector: admitted.vector,
                taint: admitted.taint,
                generation,
            },
            metric,
            signature,
            observed,
            conditional: false,
        })
    }

    pub(crate) async fn publish(
        &self,
        space_name: &str,
        mut prepared: PreparedEntry,
    ) -> Result<bool, ObservedFailure> {
        let input_taint = prepared.entry.taint.clone();
        loop {
            let result = match self.publish_now(space_name, prepared) {
                PublishAttempt::Complete(result) => result,
                PublishAttempt::Signature(pending, ann) => {
                    prepared = *pending;
                    let Some(vector) = prepared.entry.vector.dense() else {
                        return Err(ObservedFailure::from(DriverError::Other(
                            "ANN requires a dense vector".into(),
                        ))
                        .with_taint(&input_taint));
                    };
                    prepared.signature =
                        Some(ann.signature(vector, &mut Work::new(&self.config)).await);
                    continue;
                }
            };
            return match result {
                Ok(published) => Ok(published),
                Err((error, snapshot)) => {
                    let taint = if let Some(snapshot) = snapshot {
                        snapshot
                            .observed_sources(&input_taint, &mut Work::new(&self.config))
                            .await
                    } else {
                        input_taint
                    };
                    Err(ObservedFailure { error, taint })
                }
            };
        }
    }

    fn publish_now(&self, name: &str, prepared: PreparedEntry) -> PublishAttempt {
        loop {
            let existing = self.spaces.read().get(name).cloned();
            let space = existing.unwrap_or_else(|| {
                self.spaces
                    .write()
                    .entry(name.into())
                    .or_insert_with(|| {
                        Arc::new(Space {
                            state: Mutex::new(Some(SpaceIndex::new(
                                prepared.entry.vector.dimensions(),
                                prepared.entry.vector.family(),
                                prepared.metric,
                            ))),
                            building_ann: AtomicBool::new(false),
                        })
                    })
                    .clone()
            });
            let mut state = space.state.lock();
            let Some(index) = state.as_mut() else {
                drop(state);
                self.retire(name, &space);
                continue;
            };
            if !index.matches(&prepared.entry.vector, prepared.metric) {
                return PublishAttempt::Complete(Err((
                    admission::invalid("embedding no longer matches its index space"),
                    Some(index.current.clone()),
                )));
            }
            if prepared.conditional
                && !match (index.entry(&prepared.entry.id), prepared.observed.as_ref()) {
                    (None, None) => true,
                    (Some(current), Some(observed)) => Arc::ptr_eq(current, observed),
                    _ => false,
                }
            {
                return PublishAttempt::Complete(Ok(false));
            }
            if prepared.signature.is_none()
                && let Some(ann) = &index.current.ann
            {
                // An auto search may have published this accelerator after
                // admission. Preserve it and calculate only the missing signature
                // outside the lock, then recheck the same mutation condition.
                return PublishAttempt::Signature(Box::new(prepared), ann.clone());
            }
            return PublishAttempt::Complete(
                index
                    .upsert(prepared.entry, prepared.signature)
                    .map(|()| true)
                    .map_err(|error| {
                        (
                            DriverError::Other(error.into()),
                            Some(index.current.clone()),
                        )
                    }),
            );
        }
    }

    pub(crate) fn delete_generation(
        &self,
        name: &str,
        id: &str,
        generation: Option<&str>,
    ) -> Result<bool, DriverError> {
        self.delete_with_sources(name, id, generation)
            .map(|(removed, _)| removed)
    }

    fn delete_with_sources(
        &self,
        name: &str,
        id: &str,
        generation: Option<&str>,
    ) -> Result<(bool, Option<Arc<Snapshot>>), DriverError> {
        let Some(space) = self.spaces.read().get(name).cloned() else {
            return Ok((false, None));
        };
        let mut state = space.state.lock();
        let Some(index) = state.as_mut() else {
            return Ok((false, None));
        };
        let observed = index.current.clone();
        let removed = index
            .delete(id, generation)
            .map_err(|error| DriverError::Other(error.into()))?;
        let empty = index.is_empty();
        if empty {
            *state = None;
        }
        drop(state);
        if empty {
            self.retire(name, &space);
        }
        Ok((removed, Some(observed)))
    }

    fn retire(&self, name: &str, space: &Arc<Space>) {
        let mut spaces = self.spaces.write();
        if spaces
            .get(name)
            .is_some_and(|current| Arc::ptr_eq(current, space))
        {
            drop(spaces.remove(name));
        }
    }

    fn snapshot(&self, name: &str) -> Option<Arc<Snapshot>> {
        let space = self.spaces.read().get(name).cloned()?;
        space
            .state
            .lock()
            .as_ref()
            .map(|index| index.current.clone())
    }

    async fn search(
        &self,
        input: &ValueMap,
        taint: &TaintSet,
    ) -> Result<DriverOutput, ObservedFailure> {
        self.search_with_missing(input, taint, false).await
    }

    pub(crate) async fn search_or_empty(
        &self,
        input: &ValueMap,
        taint: &TaintSet,
    ) -> Result<DriverOutput, ObservedFailure> {
        self.search_with_missing(input, taint, true).await
    }

    async fn search_with_missing(
        &self,
        input: &ValueMap,
        taint: &TaintSet,
        empty_missing: bool,
    ) -> Result<DriverOutput, ObservedFailure> {
        let name = text_field(input, "space_id")?;
        let k = parse_search_limit(input.get("k"))?;
        let mode = parse_search_mode(input.get("mode"))?;
        let metric = input
            .get("metric")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| admission::invalid("index metric must be a string"))
            })
            .transpose()?;
        let representation = representation(input)?;
        let admitted = admission::admit(representation, &self.config, taint).await?;
        let Some(mut snapshot) = self.snapshot(name) else {
            return if empty_missing {
                Ok(DriverOutput::new(Outcome::Done(Value::list(Vec::new())))
                    .with_taint(admitted.taint))
            } else {
                Err(ObservedFailure::from(admission::invalid(format!(
                    "index space {name:?} does not exist"
                )))
                .with_taint(&admitted.taint))
            };
        };
        let mut work = Work::new(&self.config);
        if snapshot.dimensions != admitted.vector.dimensions()
            || snapshot.family != admitted.vector.family()
            || metric.is_some_and(|metric| {
                Metric::parse(Some(metric), admitted.vector.family()).ok() != Some(snapshot.metric)
            })
        {
            return Err(ObservedFailure {
                error: admission::invalid(
                    "query does not match the index space's representation, dimension, or metric",
                ),
                taint: snapshot.observed_sources(&admitted.taint, &mut work).await,
            });
        }
        if k != 0 && mode == SearchMode::Auto && snapshot.wants_ann() && snapshot.ann.is_none() {
            let space = self.spaces.read().get(name).cloned();
            if let Some(space) = space
                && space
                    .building_ann
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                let _owner = BuildOwner(&space.building_ann);
                let ann = LshIndex::build(&snapshot.entries, snapshot.dimensions, &mut work).await;
                let mut updated = snapshot.as_ref().clone();
                updated.ann = Some(ann);
                let updated = Arc::new(updated);
                if let Some(index) = space.state.lock().as_mut()
                    && Arc::ptr_eq(&index.current, &snapshot)
                {
                    index.current = updated.clone();
                }
                snapshot = updated;
            }
        }
        let result = snapshot
            .search(&admitted.vector, &admitted.taint, k, mode, &self.config)
            .await;
        #[cfg(test)]
        self.last_search_examined
            .store(result.examined, Ordering::Relaxed);
        let mut hits = Vec::new();
        for hit in result.hits {
            let mut fields = BTreeMap::from([
                ("id".into(), Value::string(hit.id)),
                ("sim".into(), Value::float(FloatBits(hit.score))),
            ]);
            if let Some(generation) = hit.generation {
                fields.insert("generation".into(), Value::from(generation));
            }
            hits.push(Value::map(fields));
            work.tick().await;
        }
        Ok(DriverOutput::new(Outcome::Done(Value::list(hits))).with_taint(result.taint))
    }

    async fn upsert_one(
        &self,
        input: &Value,
        taint: &TaintSet,
    ) -> Result<TaintSet, ObservedFailure> {
        let fields = input
            .as_map()
            .ok_or_else(|| admission::invalid("index upsert requires a map"))?;
        let space = text_field(fields, "space_id")?;
        let id = text_field(fields, "id")?.to_owned();
        let generation = fields
            .get("generation")
            .cloned()
            .map(|value| {
                value
                    .into_text()
                    .ok_or_else(|| admission::invalid("index generation must be a string"))
            })
            .transpose()?;
        let metric = fields
            .get("metric")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| admission::invalid("index metric must be a string"))
            })
            .transpose()?;
        let prepared = self
            .prepare(
                space,
                id,
                representation(fields)?,
                generation,
                metric,
                taint,
            )
            .await?;
        let taint = prepared.taint().clone();
        self.publish(space, prepared).await?;
        Ok(taint)
    }
}

enum PublishAttempt {
    Complete(Result<bool, (DriverError, Option<Arc<Snapshot>>)>),
    Signature(Box<PreparedEntry>, LshIndex),
}

struct BuildOwner<'a>(&'a AtomicBool);
impl Drop for BuildOwner<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn text_field<'a>(fields: &'a ValueMap, field: &str) -> Result<&'a str, DriverError> {
    fields
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| admission::invalid(format!("index requires a nonempty {field} string")))
}

fn representation(fields: &ValueMap) -> Result<EmbeddingRepresentation, DriverError> {
    EmbeddingRepresentation::from_value(
        fields
            .get("representation")
            .cloned()
            .ok_or_else(|| admission::invalid("index requires an explicit representation"))?,
    )
    .map_err(admission::invalid)
}

fn parse_search_limit(value: Option<&Value>) -> Result<usize, DriverError> {
    match value.map(Value::view) {
        Some(ValueView::Int(k)) if k >= 0 => usize::try_from(k)
            .map_err(|_error| admission::invalid("index k does not fit this platform")),
        None => Ok(10),
        _ => Err(admission::invalid("index k must be a nonnegative integer")),
    }
}

fn parse_search_mode(value: Option<&Value>) -> Result<SearchMode, DriverError> {
    match value.and_then(Value::as_str) {
        None if value.is_none() => Ok(SearchMode::Auto),
        Some("auto") => Ok(SearchMode::Auto),
        Some("exact") => Ok(SearchMode::Exact),
        _ => Err(admission::invalid(
            "index search mode must be auto or exact",
        )),
    }
}

#[async_trait]
impl Driver for IndexDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let result = match method.get() {
            0 => {
                if let Some(items) = input.as_list() {
                    let mut values = Vec::new();
                    let mut taint = ctx.taint.clone();
                    for item in items {
                        match self.upsert_one(item, &ctx.taint).await {
                            Ok(sources) => {
                                taint.union(&sources);
                                values.push(Value::boolean(true));
                            }
                            Err(error) => return error.with_taint(&taint).into_output("index"),
                        }
                    }
                    Ok(DriverOutput::new(Outcome::Done(Value::list(values))).with_taint(taint))
                } else {
                    self.upsert_one(&input, &ctx.taint).await.map(|taint| {
                        DriverOutput::new(Outcome::Done(Value::boolean(true))).with_taint(taint)
                    })
                }
            }
            1 => {
                let fields = crate::input::map(input, "index.search")?;
                self.search(&fields, &ctx.taint).await
            }
            2 => {
                let fields = crate::input::map(input, "index.delete")?;
                let name = text_field(&fields, "space_id")?;
                let id = text_field(&fields, "id")?;
                let generation = fields
                    .get("generation")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| admission::invalid("index generation must be a string"))
                    })
                    .transpose()?;
                let (removed, snapshot) = self.delete_with_sources(name, id, generation)?;
                let taint = if let Some(snapshot) = snapshot {
                    snapshot
                        .observed_sources(&ctx.taint, &mut Work::new(&self.config))
                        .await
                } else {
                    ctx.taint.clone()
                };
                Ok(DriverOutput::new(Outcome::Done(Value::boolean(removed))).with_taint(taint))
            }
            _ => return Err(DriverError::NoSuchMethod(method)),
        };
        match result {
            Ok(output) => Ok(output),
            Err(error) => error.into_output("index"),
        }
    }
}

#[cfg(test)]
mod tests;
