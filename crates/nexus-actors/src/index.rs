//! Vector Index (§17.2): `effect://index/upsert`,
//! `effect://index/search`, `effect://index/delete`.
//!
//! Retrieval goes through a Vector Index, **not** a linear scan over memory
//! (§17.2). This crate ships an in-memory brute-force cosine index — adequate
//! for the spine and small deployments — behind the same method contract a
//! production HNSW / Faiss / pgvector Driver implements, so `recall` code never
//! changes. The `space_id` isolates vectors from different embedding models
//! (§17.1): a search in one space never compares against another, and a
//! cross-space query is rejected rather than returning a meaningless score.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{FloatBits, MethodId, Outcome, OutputMode, Purity, Value};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://index/<method>` Resource with public method
/// `invoke`.
pub const INDEX_METHODS: &[MethodSpec] = &[
    MethodSpec::new("upsert", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable(),
    MethodSpec::new("search", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

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

/// In-memory vector index, partitioned by `space_id` (§17.1). Shared + cheap to
/// clone (the store is `Arc`-wrapped) so the Driver can be registered once.
#[derive(Clone, Default)]
pub struct IndexDriver {
    spaces: Arc<Mutex<HashMap<String, Vec<Entry>>>>,
    shapes: Arc<Mutex<HashMap<String, SpaceShape>>>,
}

impl IndexDriver {
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
                Value::Float(FloatBits(f)) => Ok(*f as f32),
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
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
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
                let spaces = self.spaces.lock();
                let entries = match spaces.get(&space) {
                    Some(e) => e,
                    None => {
                        return Err(DriverError::Other(format!(
                            "index space {space:?} does not exist"
                        )));
                    }
                };
                let shape = self.shapes.lock().get(&space).copied().ok_or_else(|| {
                    DriverError::Other(format!("index space {space:?} has no shape"))
                })?;
                if query.len() != shape.dims {
                    return Err(DriverError::Other(format!(
                        "query_vec dimension {} does not match index space {space:?} dimension {}",
                        query.len(),
                        shape.dims
                    )));
                }
                let mut scored: Vec<(String, f32)> = entries
                    .iter()
                    .map(|e| (e.id.clone(), cosine(&query, &e.vector)))
                    .collect();
                scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                scored.truncate(k);
                let list = scored
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
                let entries = spaces.get_mut(&space).ok_or_else(|| {
                    DriverError::Other(format!("index space {space:?} does not exist"))
                })?;
                let before = entries.len();
                entries.retain(|e| e.id != id);
                if entries.len() == before {
                    return Err(DriverError::Other(format!(
                        "index entry {id:?} does not exist in space {space:?}"
                    )));
                }
                if entries.is_empty() {
                    spaces.remove(&space);
                    self.shapes.lock().remove(&space);
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
        let mut shapes = self.shapes.lock();
        match shapes.get(&space).copied() {
            Some(shape) if shape.dims != vector.len() => {
                return Err(DriverError::Other(format!(
                    "vector dimension {} does not match index space {space:?} dimension {}",
                    vector.len(),
                    shape.dims
                )));
            }
            Some(_) => {}
            None => {
                shapes.insert(space.clone(), SpaceShape { dims: vector.len() });
            }
        }
        let entries = spaces.entry(space).or_default();
        if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
            e.vector = vector;
        } else {
            entries.push(Entry { id, vector });
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
        // Search a different space rejects instead of returning a misleading
        // "no results" answer (§17.1/§17.2).
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
