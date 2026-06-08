//! Vector Index: `effect://index/upsert`,
//! `effect://index/search`, `effect://index/delete`.
//!
//! Retrieval goes through a Vector Index. This crate ships an in-memory ANN
//! index using deterministic random
//! hyperplane LSH; tiny spaces use exact cosine scoring, while larger spaces
//! score only a bounded candidate set. The same method contract can be backed
//! by other vector stores, so `recall` code does not depend on one index
//! implementation.
//! The `space_id` isolates vectors from different embedding models: a
//! search in one space is evaluated only against that same space, and a
//! cross-space query is rejected.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{FloatBits, MethodId, Outcome, OutputMode, Purity, Value};
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://index/<method>` Resource with public method
/// `invoke`.
pub const INDEX_METHODS: &[MethodSpec] = &[
    MethodSpec::new("upsert", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable(),
    MethodSpec::new("search", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

/// Exact search is still cheaper and more accurate for small local indexes.
/// Above this size, the driver switches to ANN candidate generation so
/// million-vector recall cannot degrade into a full scan.
const EXACT_SEARCH_LIMIT: usize = 4096;
const LSH_TABLES: usize = 16;
const LSH_BITS: usize = 6;
const ANN_CANDIDATE_FLOOR: usize = 128;
const ANN_CANDIDATE_MULTIPLIER: usize = 32;
const HYPERPLANE_CACHE_LIMIT: usize = 16;
const HYPERPLANE_CACHE_MAX_DIMS: usize = 8192;
type Hyperplanes = Vec<[[f32; LSH_BITS]; LSH_TABLES]>;

struct HyperplaneCache {
    entries: HashMap<usize, Arc<Hyperplanes>>,
    insertion_order: VecDeque<usize>,
}

impl HyperplaneCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn get(&self, dims: usize) -> Option<Arc<Hyperplanes>> {
        self.entries.get(&dims).cloned()
    }

    fn insert(&mut self, dims: usize, hyperplanes: Arc<Hyperplanes>) -> Arc<Hyperplanes> {
        if let Some(cached) = self.get(dims) {
            return cached;
        }
        while self.entries.len() >= HYPERPLANE_CACHE_LIMIT {
            let Some(evict) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&evict);
        }
        self.insertion_order.push_back(dims);
        self.entries.insert(dims, hyperplanes.clone());
        hyperplanes
    }
}

static HYPERPLANE_CACHE: OnceLock<RwLock<HyperplaneCache>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpaceShape {
    dims: usize,
}

/// One stored vector entry.
#[derive(Clone)]
struct Entry {
    id: String,
    vector: Vec<f32>,
}

struct SearchResult {
    scored: Vec<(String, f32)>,
    examined: usize,
}

struct SpaceIndex {
    shape: SpaceShape,
    entries: Vec<Option<Entry>>,
    ids: HashMap<String, usize>,
    buckets: Vec<HashMap<u64, Vec<usize>>>,
}

impl SpaceIndex {
    fn new(dims: usize) -> Self {
        let mut buckets = Vec::with_capacity(LSH_TABLES);
        for _ in 0..LSH_TABLES {
            buckets.push(HashMap::new());
        }
        Self {
            shape: SpaceShape { dims },
            entries: Vec::new(),
            ids: HashMap::new(),
            buckets,
        }
    }

    fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    fn len(&self) -> usize {
        self.ids.len()
    }

    fn upsert(&mut self, id: String, vector: Vec<f32>) {
        if let Some(slot) = self.ids.get(&id).copied() {
            self.remove_from_buckets(slot);
            if let Some(entry_slot) = self.entries.get_mut(slot) {
                *entry_slot = Some(Entry { id, vector });
                self.insert_into_buckets(slot);
                return;
            }
        }

        let slot = self.entries.len();
        self.ids.insert(id.clone(), slot);
        self.entries.push(Some(Entry { id, vector }));
        self.insert_into_buckets(slot);
    }

    fn delete(&mut self, id: &str) -> bool {
        let Some(slot) = self.ids.remove(id) else {
            return false;
        };
        self.remove_from_buckets(slot);
        if let Some(entry_slot) = self.entries.get_mut(slot) {
            *entry_slot = None;
        }
        true
    }

    fn search(&self, query: &[f32], k: usize) -> SearchResult {
        if k == 0 {
            return SearchResult {
                scored: Vec::new(),
                examined: 0,
            };
        }

        let slots = if self.len() <= EXACT_SEARCH_LIMIT {
            self.exact_slots()
        } else {
            self.ann_slots(query, k)
        };
        let examined = slots.len();
        let mut scored = Vec::with_capacity(examined);
        for slot in slots {
            if let Some(Some(entry)) = self.entries.get(slot) {
                scored.push((entry.id.clone(), cosine(query, &entry.vector)));
            }
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        SearchResult { scored, examined }
    }

    fn exact_slots(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| entry.as_ref().map(|_| slot))
            .collect()
    }

    fn ann_slots(&self, query: &[f32], k: usize) -> Vec<usize> {
        let budget = self.len().min(
            k.saturating_mul(ANN_CANDIDATE_MULTIPLIER)
                .max(ANN_CANDIDATE_FLOOR),
        );
        let mut slots = Vec::with_capacity(budget);
        let mut seen = HashSet::with_capacity(budget);
        let signatures = lsh_signatures(query);
        for (table, sig) in signatures.into_iter().enumerate() {
            let Some(bucket) = self.buckets.get(table).and_then(|b| b.get(&sig)) else {
                continue;
            };
            for slot in bucket {
                if seen.insert(*slot) && self.entries.get(*slot).is_some_and(Option::is_some) {
                    slots.push(*slot);
                    if slots.len() >= budget {
                        return slots;
                    }
                }
            }
        }

        if slots.len() < budget {
            self.fill_with_probe_slots(query, budget, &mut seen, &mut slots);
        }
        slots
    }

    fn fill_with_probe_slots(
        &self,
        query: &[f32],
        budget: usize,
        seen: &mut HashSet<usize>,
        slots: &mut Vec<usize>,
    ) {
        if self.entries.is_empty() || slots.len() >= budget {
            return;
        }
        let len = self.entries.len();
        let seed = vector_seed(query);
        let start = (seed as usize) % len;
        let mut step = ((seed >> 32) as usize % len).max(1);
        if step.is_multiple_of(2) {
            step = step.saturating_add(1);
            if step >= len {
                step = 1;
            }
        }
        let max_attempts = len.min(budget.saturating_mul(8).max(ANN_CANDIDATE_FLOOR));
        for attempt in 0..max_attempts {
            let slot = (start + attempt.saturating_mul(step)) % len;
            if seen.insert(slot) && self.entries.get(slot).is_some_and(Option::is_some) {
                slots.push(slot);
                if slots.len() >= budget {
                    return;
                }
            }
        }
    }

    fn insert_into_buckets(&mut self, slot: usize) {
        let Some(Some(entry)) = self.entries.get(slot) else {
            return;
        };
        for (table, sig) in lsh_signatures(&entry.vector).into_iter().enumerate() {
            if let Some(buckets) = self.buckets.get_mut(table) {
                buckets.entry(sig).or_default().push(slot);
            }
        }
    }

    fn remove_from_buckets(&mut self, slot: usize) {
        let Some(Some(entry)) = self.entries.get(slot) else {
            return;
        };
        for (table, sig) in lsh_signatures(&entry.vector).into_iter().enumerate() {
            if let Some(buckets) = self.buckets.get_mut(table) {
                let empty = if let Some(bucket) = buckets.get_mut(&sig) {
                    bucket.retain(|candidate| *candidate != slot);
                    bucket.is_empty()
                } else {
                    false
                };
                if empty {
                    buckets.remove(&sig);
                }
            }
        }
    }
}

/// In-memory vector index, partitioned by `space_id`. Shared + cheap to
/// clone (the store is `Arc`-wrapped) so the Driver can be registered once.
#[derive(Clone, Default)]
pub struct IndexDriver {
    spaces: Arc<Mutex<HashMap<String, SpaceIndex>>>,
    last_search_examined: Arc<AtomicUsize>,
}

impl IndexDriver {
    /// Create an empty in-memory vector index driver.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Parse a non-empty `[f32; n]` vector from a `Value::List` of floats/ints.
fn parse_vector(v: Option<&Value>, field: &str) -> Result<Vec<f32>, DriverError> {
    match v {
        Some(Value::List(items)) if !items.is_empty() => items
            .iter()
            .map(|x| match x {
                Value::Float(FloatBits(f))
                    if f.is_finite() && *f <= f32::MAX as f64 && *f >= f32::MIN as f64 =>
                {
                    Ok(*f as f32)
                }
                Value::Float(FloatBits(_)) => Err(DriverError::Other(format!(
                    "{field} must contain only finite f32-compatible values"
                ))),
                Value::Int(i) => Ok(*i as f32),
                other => Err(DriverError::Other(format!(
                    "{field} must contain only numeric values, got {other:?}"
                ))),
            })
            .collect(),
        Some(Value::List(_)) => Err(DriverError::Other(format!("{field} must not be empty"))),
        _ => Err(DriverError::Other(format!("{field} must be a vector list"))),
    }
}

/// Cosine similarity in [-1, 1]; 0 for degenerate (zero-norm) vectors.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (x, y) in a.iter().zip(b) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

fn lsh_signatures(vector: &[f32]) -> [u64; LSH_TABLES] {
    let hyperplanes = hyperplanes_for_dims(vector.len());
    let mut signatures = [0u64; LSH_TABLES];
    for (table, signature) in signatures.iter_mut().enumerate() {
        let mut sig = 0u64;
        for bit in 0..LSH_BITS {
            let mut dot = 0.0f32;
            for (dim, value) in vector.iter().enumerate() {
                dot += *value * hyperplanes[dim][table][bit];
            }
            if dot >= 0.0 {
                sig |= 1u64 << bit;
            }
        }
        *signature = sig;
    }
    signatures
}

fn hyperplanes_for_dims(dims: usize) -> Arc<Hyperplanes> {
    if dims > HYPERPLANE_CACHE_MAX_DIMS {
        return compute_hyperplanes(dims);
    }

    let cache = HYPERPLANE_CACHE.get_or_init(|| RwLock::new(HyperplaneCache::new()));
    if let Some(cached) = cache.read().get(dims) {
        return cached;
    }

    let computed = compute_hyperplanes(dims);
    cache.write().insert(dims, computed)
}

fn compute_hyperplanes(dims: usize) -> Arc<Hyperplanes> {
    Arc::new(
        (0..dims)
            .map(|dim| {
                std::array::from_fn(|table| {
                    std::array::from_fn(|bit| hyperplane_component(table, bit, dim))
                })
            })
            .collect(),
    )
}

fn hyperplane_component(table: usize, bit: usize, dim: usize) -> f32 {
    let mut h = blake3::Hasher::new();
    h.update(&(table as u64).to_le_bytes());
    h.update(&(bit as u64).to_le_bytes());
    h.update(&(dim as u64).to_le_bytes());
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    (n as f32 / u32::MAX as f32) * 2.0 - 1.0
}

fn vector_seed(vector: &[f32]) -> u64 {
    let mut h = blake3::Hasher::new();
    for value in vector {
        h.update(&value.to_bits().to_le_bytes());
    }
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[async_trait]
impl Driver for IndexDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            // upsert(space_id, id, vector): insert or replace one vector.
            0 => {
                if let Value::List(items) = &input {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        self.upsert_one(item)?;
                        out.push(Value::Bool(true));
                    }
                    Ok(Outcome::Done(Value::List(out)))
                } else {
                    self.upsert_one(&input)?;
                    Ok(Outcome::Done(Value::Bool(true)))
                }
            }
            // search(space_id, query_vec, k, [filter]): k nearest by cosine.
            1 => {
                let m = input.as_map().cloned().unwrap_or_default();
                let space = m
                    .get("space_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| DriverError::Other("index op requires space_id".into()))?
                    .to_string();
                let query =
                    parse_vector(m.get("query_vec").or_else(|| m.get("vector")), "query_vec")?;
                let k = m.get("k").and_then(|v| v.as_int()).unwrap_or(10).max(0) as usize;
                let search = {
                    let spaces = self.spaces.lock();
                    let index = match spaces.get(&space) {
                        Some(index) => index,
                        None => {
                            return Err(DriverError::Other(format!(
                                "index space {space:?} does not exist"
                            )));
                        }
                    };
                    if query.len() != index.shape.dims {
                        return Err(DriverError::Other(format!(
                            "query_vec dimension {} does not match index space {space:?} dimension {}",
                            query.len(),
                            index.shape.dims
                        )));
                    }
                    index.search(&query, k)
                };
                self.last_search_examined
                    .store(search.examined, Ordering::Relaxed);
                let list = search
                    .scored
                    .into_iter()
                    .map(|(id, sim)| {
                        let mut e = BTreeMap::new();
                        e.insert("id".into(), Value::Str(id));
                        e.insert("sim".into(), Value::Float(FloatBits(sim as f64)));
                        Value::Map(e)
                    })
                    .collect();
                Ok(Outcome::Done(Value::List(list)))
            }
            // delete(space_id, id): remove one vector.
            2 => {
                let m = input.as_map().cloned().unwrap_or_default();
                let space = m
                    .get("space_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| DriverError::Other("index op requires space_id".into()))?
                    .to_string();
                let id = m
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| DriverError::Other("delete requires id".into()))?
                    .to_string();
                let mut spaces = self.spaces.lock();
                let index = spaces.get_mut(&space).ok_or_else(|| {
                    DriverError::Other(format!("index space {space:?} does not exist"))
                })?;
                if !index.delete(&id) {
                    return Err(DriverError::Other(format!(
                        "index entry {id:?} does not exist in space {space:?}"
                    )));
                }
                if index.is_empty() {
                    spaces.remove(&space);
                }
                Ok(Outcome::Done(Value::Bool(true)))
            }
            _ => Err(DriverError::Other(format!(
                "unknown index method {}",
                method.get()
            ))),
        }
    }
}

impl IndexDriver {
    fn upsert_one(&self, input: &Value) -> Result<(), DriverError> {
        let m = input.as_map().cloned().unwrap_or_default();
        let space = m
            .get("space_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DriverError::Other("index op requires space_id".into()))?
            .to_string();
        let id = m
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DriverError::Other("upsert requires id".into()))?
            .to_string();
        let vector = parse_vector(m.get("vector"), "vector")?;
        let mut spaces = self.spaces.lock();
        match spaces.get_mut(&space) {
            Some(index) if index.shape.dims != vector.len() => {
                return Err(DriverError::Other(format!(
                    "vector dimension {} does not match index space {space:?} dimension {}",
                    vector.len(),
                    index.shape.dims
                )));
            }
            Some(index) => index.upsert(id, vector),
            None => {
                let mut index = SpaceIndex::new(vector.len());
                index.upsert(id, vector);
                spaces.insert(space, index);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{IdentityRef, ProcessId};

    fn vec_val(xs: &[f32]) -> Value {
        Value::List(
            xs.iter()
                .map(|x| Value::Float(FloatBits(*x as f64)))
                .collect(),
        )
    }

    async fn upsert(d: &IndexDriver, space: &str, id: &str, v: &[f32]) {
        let mut m = BTreeMap::new();
        m.insert("space_id".into(), Value::Str(space.into()));
        m.insert("id".into(), Value::Str(id.into()));
        m.insert("vector".into(), vec_val(v));
        d.call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
    }

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn patterned_vec(i: usize) -> Vec<f32> {
        (0..8)
            .map(|dim| {
                let n = ((i * 31) + (dim * 17)) % 97;
                (n as f32 / 48.0) - 1.0
            })
            .collect()
    }

    #[tokio::test]
    async fn search_ranks_nearest_in_space() {
        let d = IndexDriver::new();
        upsert(&d, "s1", "a", &[1.0, 0.0, 0.0]).await;
        upsert(&d, "s1", "b", &[0.0, 1.0, 0.0]).await;
        upsert(&d, "s1", "c", &[0.9, 0.1, 0.0]).await;
        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str("s1".into()));
        q.insert("query_vec".into(), vec_val(&[1.0, 0.0, 0.0]));
        q.insert("k".into(), Value::Int(2));
        let out = d
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(results)) => {
                assert_eq!(results.len(), 2);
                // Nearest is "a" (identical direction), then "c".
                let first = results[0]
                    .as_map()
                    .unwrap()
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap();
                assert_eq!(first, "a");
            }
            _ => panic!("expected ranked list"),
        }
    }

    #[tokio::test]
    async fn large_search_scores_bounded_ann_candidates() {
        let d = IndexDriver::new();
        for i in 0..(EXACT_SEARCH_LIMIT + 256) {
            let vector = patterned_vec(i);
            upsert(&d, "big", &format!("v{i}"), &vector).await;
        }

        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str("big".into()));
        q.insert("query_vec".into(), vec_val(&patterned_vec(17)));
        q.insert("k".into(), Value::Int(10));
        let out = d
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(results)) => assert_eq!(results.len(), 10),
            other => panic!("expected ANN results, got {other:?}"),
        }

        let examined = d.last_search_examined.load(Ordering::Relaxed);
        assert!(
            examined <= ANN_CANDIDATE_FLOOR.max(10 * ANN_CANDIDATE_MULTIPLIER),
            "large search examined {examined} candidates"
        );
    }

    #[tokio::test]
    async fn upsert_is_batchable_list_in_list_out() {
        let d = IndexDriver::new();
        let item = |id: &str, v: &[f32]| {
            let mut m = BTreeMap::new();
            m.insert("space_id".into(), Value::Str("s1".into()));
            m.insert("id".into(), Value::Str(id.into()));
            m.insert("vector".into(), vec_val(v));
            Value::Map(m)
        };
        let out = d
            .call(
                MethodId::new(0),
                Value::List(vec![
                    item("a", &[1.0, 0.0, 0.0]),
                    item("b", &[0.0, 1.0, 0.0]),
                ]),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        assert_eq!(
            out,
            Outcome::Done(Value::List(vec![Value::Bool(true), Value::Bool(true)]))
        );

        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str("s1".into()));
        q.insert("query_vec".into(), vec_val(&[1.0, 0.0, 0.0]));
        let search = d
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match search {
            Outcome::Done(Value::List(results)) => assert_eq!(results.len(), 2),
            other => panic!("expected indexed batch results, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_space_is_rejected() {
        let d = IndexDriver::new();
        upsert(&d, "s1", "a", &[1.0, 0.0]).await;
        // Searching a different space is rejected.
        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str("s2".into()));
        q.insert("query_vec".into(), vec_val(&[1.0, 0.0]));
        let out = d
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx())
            .await;
        assert!(out.is_err());
    }

    #[tokio::test]
    async fn dimension_mismatch_is_rejected() {
        let d = IndexDriver::new();
        upsert(&d, "s1", "a", &[1.0, 0.0]).await;

        let mut up = BTreeMap::new();
        up.insert("space_id".into(), Value::Str("s1".into()));
        up.insert("id".into(), Value::Str("b".into()));
        up.insert("vector".into(), vec_val(&[1.0, 0.0, 0.0]));
        let out = d
            .call(MethodId::new(0), Value::Map(up), OutputMode::Unary, &ctx())
            .await;
        assert!(out.is_err());

        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str("s1".into()));
        q.insert("query_vec".into(), vec_val(&[1.0, 0.0, 0.0]));
        let search = d
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx())
            .await;
        assert!(search.is_err());
    }

    #[tokio::test]
    async fn delete_removes_space_when_last_entry_is_removed() {
        let d = IndexDriver::new();
        upsert(&d, "s1", "a", &[1.0, 0.0]).await;

        let mut del = BTreeMap::new();
        del.insert("space_id".into(), Value::Str("s1".into()));
        del.insert("id".into(), Value::Str("a".into()));
        let out = d
            .call(MethodId::new(2), Value::Map(del), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Bool(true)));

        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str("s1".into()));
        q.insert("query_vec".into(), vec_val(&[1.0, 0.0]));
        let search = d
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx())
            .await;
        assert!(search.is_err());
    }

    #[tokio::test]
    async fn missing_space_id_errors() {
        let d = IndexDriver::new();
        let out = d
            .call(
                MethodId::new(1),
                Value::Map(BTreeMap::new()),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        assert!(out.is_err());
    }
}
