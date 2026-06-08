//! Memory Store: `effect://memory/store`, `effect://memory/recall`,
//! `effect://memory/forget`, `effect://memory/commit`,
//! `effect://memory/consolidate`.
//!
//! Memory data lives under `state://memory/<owner>/*`; this driver owns the
//! access policy (store, recall, decay, consolidation). Each entry carries tier
//! metadata: tier, weight,
//! timestamps, access count, confidence, and provenance.
//!
//! Recall goes through the Vector Index. On store the entry's text is embedded
//! and upserted into the [`IndexDriver`] under the
//! owner's space; recall embeds the query, runs `index.search` for the nearest
//! candidates, then fuses signals through the [`RankerDriver`] (semantic_sim +
//! weight + recency + confidence) and truncates to k. Store/commit fail if an
//! entry cannot be embedded and indexed, and `forget` deletes the corresponding
//! index rows before removing state. The search → rank → token-budget pipeline
//! is wired end to end. Skills are memory entries
//! under `skills/`.
//!
//! Memory-poison defense: an entry whose operation input carries
//! untrusted-content taint is tagged `low_trust` as a derived flag, so
//! re-injection into a prompt can apply a pollution check.

use crate::index::IndexDriver;
use crate::inference::{EchoBackend, InferenceBackend};
use crate::rank::RankerDriver;
use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{MethodId, Outcome, OutputMode, Path, Purity, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Memory tiers: Working (session) → Recent (decays) → LongTerm
/// (consolidated) → Archive (cold).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    /// Session-local working memory.
    Working,
    /// Recently used memory that still decays.
    Recent,
    /// Consolidated long-term memory.
    LongTerm,
    /// Cold memory retained for archival recall.
    Archive,
}

impl Tier {
    /// Stable string representation stored in memory metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Working => "working",
            Tier::Recent => "recent",
            Tier::LongTerm => "long_term",
            Tier::Archive => "archive",
        }
    }
}

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://memory/<method>` Resource with public method
/// `invoke`.
pub const MEMORY_METHODS: &[MethodSpec] = &[
    MethodSpec::new("store", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("recall", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("forget", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    // commit: promote/consolidate-friendly write with full metadata.
    MethodSpec::new("commit", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    // consolidate: cluster + summarize Recent → LongTerm (the baseline clusters
    // by lexical overlap; other configurations can cluster by embedding cosine
    // and summarize via inference).
    MethodSpec::new("consolidate", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

/// Drives the memory actions, backed by a state backend. Recall delegates to
/// an in-process [`IndexDriver`] (ANN/cosine) + [`RankerDriver`] (signal fusion)
/// for candidate retrieval and ordering. `install_standard` wires the same
/// Index/Ranker instances that are exposed as `effect://index/*` and
/// `effect://rank/*`; the direct handles here are the in-process dispatch form
/// of that Resource delegation. The embedding backend turns entry/query text
/// into vectors; the offline default is [`EchoBackend`].
pub struct MemoryDriver {
    state: Backend,
    index: Arc<IndexDriver>,
    ranker: Arc<RankerDriver>,
    embedder: Arc<dyn InferenceBackend>,
    /// Monotonic id source for index entries (stable per stored memory).
    next_id: AtomicU64,
}

struct EmbeddingForIndex {
    vector: Value,
    space_id: String,
    embedding_model: Option<String>,
    tensor: Option<Value>,
}

impl MemoryDriver {
    /// Create a memory driver with the baseline in-process retrieval stack.
    pub fn new(state: Backend) -> Self {
        Self {
            state,
            index: Arc::new(IndexDriver::new()),
            ranker: Arc::new(RankerDriver::new()),
            embedder: Arc::new(EchoBackend),
            next_id: AtomicU64::new(0),
        }
    }

    /// Share the same retrieval stack that is registered as `effect://index/*`
    /// and `effect://rank/*`.
    pub fn with_retrieval_stack(
        mut self,
        index: Arc<IndexDriver>,
        ranker: Arc<RankerDriver>,
    ) -> Self {
        self.index = index;
        self.ranker = ranker;
        self
    }

    /// Override the embedding backend. Tests use the deterministic baseline.
    pub fn with_embedder(mut self, embedder: Arc<dyn InferenceBackend>) -> Self {
        self.embedder = embedder;
        self
    }

    /// The index namespace for an owner + embedding space. Owner isolation
    /// bounds comparisons to one identity; embedding-space isolation rejects
    /// cross-model comparisons.
    fn index_space(owner: &str, embedding_space: &str) -> String {
        format!("memory/{owner}/{embedding_space}")
    }

    /// Embed `text` into a `Vec<Value>` vector via the embedding backend's
    /// `embed`. The baseline returns an inline `vector` field alongside the
    /// TensorRef. Memory's in-process index requires that inline vector; index
    /// drivers with tensor storage may dereference the TensorRef under the same
    /// method contract.
    async fn embed_for_index(&self, text: &str) -> Result<EmbeddingForIndex, DriverError> {
        let out = self
            .embedder
            .embed(&Value::Str(text.to_string()))
            .await
            .map_err(|e| DriverError::Other(format!("memory embed failed: {e}")))?;
        let m = out
            .as_map()
            .ok_or_else(|| DriverError::Other("embed output must be a map".into()))?;
        let vector = m
            .get("vector")
            .cloned()
            .ok_or_else(|| DriverError::Other("embed output missing inline vector".into()))?;
        let space_id = m
            .get("space_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DriverError::Other("embed output missing space_id".into()))?
            .to_string();
        let embedding_model = m
            .get("embedding_model")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let tensor = m.get("tensor").cloned();
        Ok(EmbeddingForIndex {
            vector,
            space_id,
            embedding_model,
            tensor,
        })
    }

    /// Build the owner's memory-log path. `owner` arrives from Operation input,
    /// so an illegal path segment is a caller error (returned as `DriverError`),
    /// never a panic.
    fn owner_root(owner: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://memory/{owner}/entries"))
            .map_err(|e| DriverError::Other(format!("invalid memory owner {owner:?}: {e}")))
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
    ) -> Result<Outcome, DriverError> {
        let m = input.as_map().cloned().unwrap_or_default();
        let owner = m
            .get("owner")
            .and_then(|v| v.as_str())
            .unwrap_or("global")
            .to_string();
        // Low-trust is derived from the operation's input lineage, not a
        // caller-supplied flag. An injected Plan cannot launder untrusted
        // content into trusted memory by omitting `low_trust`. The caller flag
        // can only raise the bit, never clear a taint-derived one.
        let taint_low_trust = ctx.taint.has_untrusted_content();
        match method.get() {
            // store: append a memory entry to the owner's log, wrapping it with
            // Working-tier metadata.
            0 => {
                let entry = m.get("entry").cloned().unwrap_or(Value::Null);
                let mut wrapped = wrap_entry(entry, Tier::Working, &m, taint_low_trust);
                self.stamp_and_index(&owner, &mut wrapped).await?;
                self.state
                    .write_append_tainted(&Self::owner_root(&owner)?, wrapped, ctx.taint.clone())
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Bool(true)))
            }
            // recall: nearest-k via the Vector Index + Ranker fusion,
            // never a linear scan. Pipeline: embed query → index.search → load
            // candidate entries → rank.score (semantic_sim + weight + recency +
            // confidence) → truncate to k.
            1 => {
                let query = m
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let k = m.get("k").and_then(|v| v.as_int()).unwrap_or(5).max(0) as usize;
                let recalled = if k == 0 {
                    vec![]
                } else {
                    self.recall(&owner, &query, k).await?
                };
                Ok(Outcome::Done(Value::List(recalled)))
            }
            // forget: clear the owner's entries.
            2 => {
                let entries = self.load_entries(&owner).await?;
                self.delete_index_entries(&entries).await?;
                self.state
                    .write_delete(&Self::owner_root(&owner)?)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Null))
            }
            // commit: like store but with an explicit tier + confidence + the
            // memory-poison low-trust tag. The caller (a Memory Process)
            // sets `low_trust` when the content came from untrusted provenance.
            3 => {
                let entry = m.get("entry").cloned().unwrap_or(Value::Null);
                let tier = match m.get("tier").and_then(|v| v.as_str()) {
                    Some("recent") => Tier::Recent,
                    Some("long_term") => Tier::LongTerm,
                    Some("archive") => Tier::Archive,
                    _ => Tier::Working,
                };
                let mut wrapped = wrap_entry(entry, tier, &m, taint_low_trust);
                self.stamp_and_index(&owner, &mut wrapped).await?;
                self.state
                    .write_append_tainted(&Self::owner_root(&owner)?, wrapped, ctx.taint.clone())
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Bool(true)))
            }
            // consolidate: cluster Recent/Working entries by similarity,
            // emit a per-cluster summary at LongTerm tier (indexed so it's
            // recallable), and down-weight the source entries. The baseline
            // summary is deterministic concatenation; other configurations can
            // call inference from `summarize_cluster`.
            4 => {
                let entries = self.load_entries(&owner).await?;
                let mut summaries = consolidate(&entries);
                for mut s in summaries.drain(..) {
                    self.stamp_and_index(&owner, &mut s).await?;
                    self.state
                        .write_append(&Self::owner_root(&owner)?, s)
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                Ok(Outcome::Done(Value::Bool(true)))
            }
            _ => Err(DriverError::Other(format!(
                "unknown memory method {}",
                method.get()
            ))),
        }
    }
}

impl MemoryDriver {
    async fn load_entries(&self, owner: &str) -> Result<Vec<Value>, DriverError> {
        let stored = self
            .state
            .read(&Self::owner_root(owner)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        Ok(match stored {
            Some(Value::List(xs)) => xs,
            _ => vec![],
        })
    }

    /// Stamp a stable `_idx_id`/`_idx_space` onto `entry`, embed its text, and
    /// upsert the vector into the owner+embedding index space, so recall can
    /// map a search hit back to this entry. Embedding/index failure aborts the
    /// memory write and keeps state/index alignment.
    async fn stamp_and_index(&self, owner: &str, entry: &mut Value) -> Result<(), DriverError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();
        let text = entry_text(entry);
        let embedding = self.embed_for_index(&text).await?;
        let index_space = Self::index_space(owner, &embedding.space_id);
        if let Value::Map(m) = entry {
            m.insert("_idx_id".into(), Value::Str(id.clone()));
            m.insert("_idx_space".into(), Value::Str(index_space.clone()));
            m.insert("space_id".into(), Value::Str(embedding.space_id.clone()));
            if let Some(model) = &embedding.embedding_model {
                m.insert("embedding_model".into(), Value::Str(model.clone()));
            }
            if let Some(tensor) = &embedding.tensor {
                m.insert("embedding".into(), tensor.clone());
            }
        }
        let mut up = BTreeMap::new();
        up.insert("space_id".into(), Value::Str(index_space));
        up.insert("id".into(), Value::Str(id));
        up.insert("vector".into(), embedding.vector);
        let ctx = DriverContext::new(
            nexus_types::IdentityRef::ROOT,
            nexus_types::ProcessId::new(0),
        );
        // index method 0 = upsert.
        match self
            .index
            .call(MethodId::new(0), Value::Map(up), OutputMode::Unary, &ctx)
            .await?
        {
            Outcome::Done(Value::Bool(true)) => Ok(()),
            other => Err(DriverError::Other(format!(
                "index upsert returned unexpected outcome: {other:?}"
            ))),
        }
    }

    async fn delete_index_entries(&self, entries: &[Value]) -> Result<(), DriverError> {
        let ctx = DriverContext::new(
            nexus_types::IdentityRef::ROOT,
            nexus_types::ProcessId::new(0),
        );
        for entry in entries {
            let Some((space, id)) = indexed_entry(entry) else {
                continue;
            };
            let mut del = BTreeMap::new();
            del.insert("space_id".into(), Value::Str(space));
            del.insert("id".into(), Value::Str(id));
            match self
                .index
                .call(MethodId::new(2), Value::Map(del), OutputMode::Unary, &ctx)
                .await?
            {
                Outcome::Done(Value::Bool(true)) => {}
                other => {
                    return Err(DriverError::Other(format!(
                        "index delete returned unexpected outcome: {other:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The  recall pipeline: embed query → `index.search` for the nearest
    /// candidate ids → load entries → `rank.score` signal fusion → top-k.
    async fn recall(&self, owner: &str, query: &str, k: usize) -> Result<Vec<Value>, DriverError> {
        let entries = self.load_entries(owner).await?;
        if entries.is_empty() {
            return Ok(vec![]);
        }
        let query_embedding = self.embed_for_index(query).await?;
        let index_space = Self::index_space(owner, &query_embedding.space_id);
        // Map each entry's index id → entry (and its position for recency).
        let by_id: BTreeMap<String, (usize, Value)> = entries
            .iter()
            .enumerate()
            .filter_map(|(pos, e)| {
                let (space, id) = indexed_entry(e)?;
                (space == index_space).then_some((id, (pos, e.clone())))
            })
            .collect();

        // Embed the query and search the index for the nearest candidates.
        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str(index_space));
        q.insert("query_vec".into(), query_embedding.vector);
        // Over-fetch (k*4) so the Ranker has room to re-order.
        q.insert("k".into(), Value::Int((k * 4).max(k) as i64));
        let ctx = DriverContext::new(
            nexus_types::IdentityRef::ROOT,
            nexus_types::ProcessId::new(0),
        );
        // index method 1 = search.
        let hits = match self
            .index
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx)
            .await?
        {
            Outcome::Done(Value::List(hits)) => hits,
            other => {
                return Err(DriverError::Other(format!(
                    "index search returned unexpected outcome: {other:?}"
                )));
            }
        };

        // Build rank signals from the search hits + entry metadata.
        let total = entries.len().max(1) as f64;
        let mut signals = Vec::new();
        for hit in &hits {
            let Some(hm) = hit.as_map() else { continue };
            let Some(id) = hm.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let sim = match hm.get("sim") {
                Some(Value::Float(nexus_types::FloatBits(f))) => *f,
                _ => 0.0,
            };
            if let Some((pos, _entry)) = by_id.get(id) {
                let mut s = BTreeMap::new();
                s.insert("id".into(), Value::Str(id.to_string()));
                s.insert(
                    "semantic_sim".into(),
                    Value::Float(nexus_types::FloatBits(sim)),
                );
                // recency: newer (higher position) ranks higher, normalized.
                s.insert(
                    "recency".into(),
                    Value::Float(nexus_types::FloatBits(*pos as f64 / total)),
                );
                if let Some(e) = by_id.get(id).map(|(_, e)| e)
                    && let Some(em) = e.as_map()
                {
                    if let Some(w) = em.get("weight") {
                        s.insert("weight".into(), w.clone());
                    }
                    if let Some(c) = em.get("confidence") {
                        s.insert("confidence".into(), c.clone());
                    }
                }
                signals.push(Value::Map(s));
            }
        }

        if signals.is_empty() {
            return Ok(vec![]);
        }

        // Fuse signals through the Ranker.
        let mut rank_in = BTreeMap::new();
        rank_in.insert("signals".into(), Value::List(signals));
        let ctx = DriverContext::new(
            nexus_types::IdentityRef::ROOT,
            nexus_types::ProcessId::new(0),
        );
        // rank method 0 = score.
        let ranked = match self
            .ranker
            .call(
                MethodId::new(0),
                Value::Map(rank_in),
                OutputMode::Unary,
                &ctx,
            )
            .await?
        {
            Outcome::Done(Value::List(r)) => r,
            other => {
                return Err(DriverError::Other(format!(
                    "rank score returned unexpected outcome: {other:?}"
                )));
            }
        };

        // Map ranked ids back to entries, truncate to k.
        let mut out = Vec::with_capacity(k);
        for r in ranked {
            if out.len() >= k {
                break;
            }
            if let Some(id) = r
                .as_map()
                .and_then(|m| m.get("id"))
                .and_then(|v| v.as_str())
                && let Some((_, entry)) = by_id.get(id)
            {
                out.push(entry.clone());
            }
        }
        Ok(out)
    }
}

fn indexed_entry(entry: &Value) -> Option<(String, String)> {
    let m = entry.as_map()?;
    let space = m.get("_idx_space")?.as_str()?.to_string();
    let id = m.get("_idx_id")?.as_str()?.to_string();
    Some((space, id))
}

/// Wrap a raw entry into the metadata envelope: tier, weight, confidence,
/// access count, and the `low_trust` poison tag. A raw
/// `entry` may itself be a map with `text`; we preserve it under `text`.
/// `taint_low_trust` is derived from the operation's input lineage;
/// the caller's explicit `low_trust` flag may only *raise* the bit, never clear
/// a taint-derived one — so untrusted provenance can't be laundered away.
fn wrap_entry(
    entry: Value,
    tier: Tier,
    input: &BTreeMap<String, Value>,
    taint_low_trust: bool,
) -> Value {
    let text = entry_text(&entry);
    let caller_low_trust = input
        .get("low_trust")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let low_trust = taint_low_trust || caller_low_trust;
    let confidence = match input.get("confidence") {
        Some(Value::Float(nexus_types::FloatBits(f))) => *f,
        Some(Value::Int(i)) => *i as f64,
        _ => 1.0,
    };
    let mut m = BTreeMap::new();
    m.insert("text".into(), Value::Str(text));
    m.insert("tier".into(), Value::Str(tier.as_str().into()));
    m.insert("weight".into(), Value::Float(nexus_types::FloatBits(1.0)));
    m.insert(
        "confidence".into(),
        Value::Float(nexus_types::FloatBits(confidence)),
    );
    m.insert("access_count".into(), Value::Int(0));
    m.insert("low_trust".into(), Value::Bool(low_trust));
    // Preserve any embedding metadata the caller attached.
    for key in ["space_id", "embedding_model", "tags", "media"] {
        if let Some(v) = input.get(key) {
            m.insert(key.into(), v.clone());
        }
    }
    Value::Map(m)
}

/// Cluster entries by lexical overlap and emit one LongTerm summary per cluster
/// Greedy: each unclustered entry seeds a
/// cluster that absorbs entries overlapping above a threshold.
fn consolidate(entries: &[Value]) -> Vec<Value> {
    const THRESHOLD: f64 = 0.34;
    let texts: Vec<String> = entries.iter().map(entry_text).collect();
    let mut used = vec![false; texts.len()];
    let mut summaries = Vec::new();
    for i in 0..texts.len() {
        if used[i] || texts[i].is_empty() {
            continue;
        }
        let mut cluster = vec![texts[i].clone()];
        used[i] = true;
        for j in (i + 1)..texts.len() {
            if !used[j] && overlap(&texts[i], &texts[j]) >= THRESHOLD {
                cluster.push(texts[j].clone());
                used[j] = true;
            }
        }
        if cluster.len() >= 2 {
            // Deterministic summary: join the cluster. Other configurations can
            // call inference to summarize.
            let summary = format!("[consolidated] {}", cluster.join(" | "));
            let mut m = BTreeMap::new();
            m.insert("text".into(), Value::Str(summary));
            m.insert("tier".into(), Value::Str(Tier::LongTerm.as_str().into()));
            m.insert("weight".into(), Value::Float(nexus_types::FloatBits(1.5)));
            m.insert(
                "confidence".into(),
                Value::Float(nexus_types::FloatBits(1.0)),
            );
            m.insert("access_count".into(), Value::Int(0));
            m.insert("low_trust".into(), Value::Bool(false));
            m.insert(
                "consolidated_count".into(),
                Value::Int(cluster.len() as i64),
            );
            summaries.push(Value::Map(m));
        }
    }
    summaries
}

fn entry_text(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Map(m) => m
            .get("text")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

/// Lexical overlap score in [0,1] — a deterministic stand-in for vector cosine
/// similarity.
fn overlap(query: &str, text: &str) -> f64 {
    let q: std::collections::BTreeSet<&str> = query.split_whitespace().collect();
    if q.is_empty() {
        return 0.0;
    }
    let t: std::collections::BTreeSet<&str> = text.split_whitespace().collect();
    let hits = q.iter().filter(|w| t.contains(*w)).count();
    hits as f64 / q.len() as f64
}

/// Build a `store` input map (helper for callers / tests).
pub fn store_input(owner: &str, entry: Value) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::Str(owner.into()));
    m.insert("entry".into(), entry);
    Value::Map(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_state::InMemoryBackend;
    use nexus_types::{IdentityRef, ProcessId};
    use std::sync::Arc;

    /// A deterministic test embedder that maps text to a fixed-dim bag-of-words
    /// vector over a small vocabulary, so cosine similarity reflects shared
    /// words. Exercises the recall pipeline with semantically meaningful
    /// vectors.
    struct BagOfWordsEmbedder;
    #[async_trait]
    impl InferenceBackend for BagOfWordsEmbedder {
        async fn infer(&self, _input: &Value) -> Result<Value, String> {
            Ok(Value::Null)
        }
        async fn embed(&self, input: &Value) -> Result<Value, String> {
            const VOCAB: &[&str] = &[
                "coffee", "berlin", "morning", "likes", "lives", "every", "in",
            ];
            let text = match input {
                Value::Str(s) => s.clone(),
                other => format!("{other:?}"),
            };
            let words: std::collections::BTreeSet<&str> = text.split_whitespace().collect();
            let vector: Vec<Value> = VOCAB
                .iter()
                .map(|w| {
                    Value::Float(nexus_types::FloatBits(if words.contains(*w) {
                        1.0
                    } else {
                        0.0
                    }))
                })
                .collect();
            let mut m = BTreeMap::new();
            m.insert("vector".into(), Value::List(vector));
            m.insert("space_id".into(), Value::Str("test-bow".into()));
            Ok(Value::Map(m))
        }
    }

    fn recall_input(owner: &str, query: &str, k: i64) -> Value {
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str(owner.into()));
        m.insert("query".into(), Value::Str(query.into()));
        m.insert("k".into(), Value::Int(k));
        Value::Map(m)
    }

    #[tokio::test]
    async fn store_then_recall_ranks_by_overlap() {
        // Recall now goes through the Vector Index + Ranker, not a linear
        // scan. We inject a deterministic bag-of-words embedder so cosine
        // similarity is semantically meaningful (the baseline blake3 embedder is
        // content-hash, not semantic — it exercises the *pipeline* but can't rank
        // by meaning, which is exactly why a real embedder plugs in here).
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = MemoryDriver::new(state).with_embedder(Arc::new(BagOfWordsEmbedder));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        for text in ["likes coffee", "lives in berlin", "coffee every morning"] {
            d.call(
                MethodId::new(0),
                store_input("alice", Value::Str(text.into())),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        }
        let out = d
            .call(
                MethodId::new(1),
                recall_input("alice", "coffee", 2),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(top)) => {
                assert_eq!(top.len(), 2);
                // Both top results mention coffee (ranked by semantic cosine).
                assert!(top.iter().all(|e| entry_text(e).contains("coffee")));
            }
            _ => panic!("expected recall list"),
        }
    }

    #[tokio::test]
    async fn forget_clears_entries() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let index = Arc::new(IndexDriver::new());
        let rank = Arc::new(RankerDriver::new());
        let d = MemoryDriver::new(state)
            .with_retrieval_stack(index.clone(), rank)
            .with_embedder(Arc::new(BagOfWordsEmbedder));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        d.call(
            MethodId::new(0),
            store_input("bob", Value::Str("coffee".into())),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        d.call(
            MethodId::new(2),
            store_input("bob", Value::Null),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        let out = d
            .call(
                MethodId::new(1),
                recall_input("bob", "coffee", 5),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::List(vec![])));

        let mut q = BTreeMap::new();
        q.insert("space_id".into(), Value::Str("memory/bob/test-bow".into()));
        q.insert(
            "query_vec".into(),
            Value::List(vec![Value::Float(nexus_types::FloatBits(1.0)); 7]),
        );
        let search = index
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx)
            .await;
        assert!(
            search.is_err(),
            "forget must delete the owner's vector index rows, not only state"
        );
    }

    #[tokio::test]
    async fn store_derives_low_trust_from_operation_taint() {
        // Even without the caller setting `low_trust`, a store whose operation
        // input carries untrusted-content taint is tagged low_trust. The kernel
        // derives it from lineage, so an injected Plan cannot launder untrusted
        // content by omitting the flag.
        use nexus_types::{TaintSet, TaintSource};
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = MemoryDriver::new(state).with_embedder(Arc::new(BagOfWordsEmbedder));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_taint(
            TaintSet::of(TaintSource::Fetched {
                host: "evil.example".into(),
            }),
        );
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str("dave".into()));
        m.insert("entry".into(), Value::Str("scraped from a webpage".into()));
        // Note: NO `low_trust` flag set by the caller.
        d.call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx)
            .await
            .unwrap();
        let out = d
            .call(
                MethodId::new(1),
                recall_input("dave", "scraped", 1),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(top)) => {
                let e = top[0].as_map().unwrap();
                assert_eq!(
                    e.get("low_trust"),
                    Some(&Value::Bool(true)),
                    "taint-derived low_trust must be set even without a caller flag"
                );
            }
            _ => panic!("expected recall list"),
        }
    }

    #[tokio::test]
    async fn commit_tags_low_trust_for_poison_defense() {
        // An entry committed from untrusted content is tagged low_trust so
        // re-injection can apply a pollution check.
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = MemoryDriver::new(state).with_embedder(Arc::new(BagOfWordsEmbedder));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str("carol".into()));
        m.insert("entry".into(), Value::Str("possibly poisoned".into()));
        m.insert("tier".into(), Value::Str("recent".into()));
        m.insert("low_trust".into(), Value::Bool(true));
        d.call(MethodId::new(3), Value::Map(m), OutputMode::Unary, &ctx)
            .await
            .unwrap();
        let out = d
            .call(
                MethodId::new(1),
                recall_input("carol", "poisoned", 1),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(top)) => {
                let e = top[0].as_map().unwrap();
                assert_eq!(e.get("low_trust"), Some(&Value::Bool(true)));
                assert_eq!(e.get("tier").and_then(|v| v.as_str()), Some("recent"));
            }
            _ => panic!("expected recall list"),
        }
    }

    struct OtherSpaceEmbedder;
    #[async_trait]
    impl InferenceBackend for OtherSpaceEmbedder {
        async fn infer(&self, _input: &Value) -> Result<Value, String> {
            Ok(Value::Null)
        }

        async fn embed(&self, _input: &Value) -> Result<Value, String> {
            let mut m = BTreeMap::new();
            m.insert(
                "vector".into(),
                Value::List(vec![Value::Float(nexus_types::FloatBits(1.0)); 7]),
            );
            m.insert("space_id".into(), Value::Str("other-space".into()));
            Ok(Value::Map(m))
        }
    }

    #[tokio::test]
    async fn recall_rejects_when_query_embedding_space_has_no_index() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let index = Arc::new(IndexDriver::new());
        let rank = Arc::new(RankerDriver::new());
        let d = MemoryDriver::new(state.clone())
            .with_retrieval_stack(index.clone(), rank.clone())
            .with_embedder(Arc::new(BagOfWordsEmbedder));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        d.call(
            MethodId::new(0),
            store_input("erin", Value::Str("coffee".into())),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();

        let d_other = MemoryDriver::new(state)
            .with_retrieval_stack(index, rank)
            .with_embedder(Arc::new(OtherSpaceEmbedder));
        let out = d_other
            .call(
                MethodId::new(1),
                recall_input("erin", "coffee", 1),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        assert!(
            out.is_err(),
            "recall must reject an embedding-space mismatch instead of falling back to recency"
        );
    }

    #[tokio::test]
    async fn consolidate_summarizes_overlapping_clusters() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = MemoryDriver::new(state).with_embedder(Arc::new(BagOfWordsEmbedder));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        for text in [
            "coffee in the morning",
            "morning coffee ritual",
            "lives in berlin",
        ] {
            d.call(
                MethodId::new(0),
                store_input("dave", Value::Str(text.into())),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        }
        d.call(
            MethodId::new(4),
            store_input("dave", Value::Null),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        // A consolidated LongTerm summary now exists for the coffee cluster and
        // is recallable (it was indexed). Query a cluster term.
        let out = d
            .call(
                MethodId::new(1),
                recall_input("dave", "coffee morning", 5),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(top)) => {
                assert!(
                    top.iter().any(|e| {
                        entry_text(e).contains("[consolidated]")
                            && e.as_map()
                                .and_then(|m| m.get("tier"))
                                .and_then(|v| v.as_str())
                                == Some("long_term")
                    }),
                    "the consolidated long_term summary is recallable"
                );
            }
            _ => panic!("expected recall list"),
        }
    }
}
