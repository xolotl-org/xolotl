//! Memory Store: `effect://memory/store`, `effect://memory/recall`,
//! `effect://memory/forget`, `effect://memory/commit`,
//! `effect://memory/consolidate`.
//!
//! Memory entries live under `state://memory/<owner>/<namespace>/<id>`. The
//! driver stores the original `content: Value` in an envelope, indexes the
//! indexable projection through the Vector Index, and recalls by loading only
//! index hits. `skills` and `persona` are namespaces, not separate runtime
//! objects.

use crate::index::IndexDriver;
use crate::inference::{EchoBackend, InferenceBackend};
use crate::rank::RankerDriver;
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use xolotl_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use xolotl_state::{Backend, StateError};
use xolotl_types::{FloatBits, MethodId, Outcome, OutputMode, Path, Purity, Value};

const DEFAULT_NAMESPACE: &str = "general";
const SKILLS_NAMESPACE: &str = "skills";

/// Memory tiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tier {
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
    /// Stable string stored in memory metadata.
    pub(crate) fn as_str(self) -> &'static str {
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
pub(crate) const MEMORY_METHODS: &[MethodSpec] = &[
    MethodSpec::new("store", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("recall", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("forget", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("commit", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("consolidate", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

/// Drives memory actions over state, vector index, ranker, and embedding.
pub(crate) struct MemoryDriver {
    state: Backend,
    index: Arc<IndexDriver>,
    ranker: Arc<RankerDriver>,
    embedder: Arc<dyn InferenceBackend>,
}

struct EmbeddingForIndex {
    vector: Value,
    space_id: String,
    embedding_model: Option<String>,
    tensor: Option<Value>,
}

#[derive(Clone)]
struct IndexedEntry {
    id: String,
    space_id: String,
}

impl MemoryDriver {
    /// Create a memory driver with the baseline in-process retrieval stack.
    pub(crate) fn new(state: Backend) -> Self {
        Self {
            state,
            index: Arc::new(IndexDriver::new()),
            ranker: Arc::new(RankerDriver::new()),
            embedder: Arc::new(EchoBackend),
        }
    }

    /// Share the same retrieval stack that is registered as `effect://index/*`
    /// and `effect://rank/*`.
    pub(crate) fn with_retrieval_stack(
        mut self,
        index: Arc<IndexDriver>,
        ranker: Arc<RankerDriver>,
    ) -> Self {
        self.index = index;
        self.ranker = ranker;
        self
    }

    /// Override the embedding backend.
    pub(crate) fn with_embedder(mut self, embedder: Arc<dyn InferenceBackend>) -> Self {
        self.embedder = embedder;
        self
    }

    fn index_space(owner: &str, namespace: &str, embedding_space: &str) -> String {
        format!("memory/{owner}/{namespace}/{embedding_space}")
    }

    async fn embed_for_index(&self, input: &Value) -> Result<EmbeddingForIndex, DriverError> {
        let out = self
            .embedder
            .embed(input)
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
        let m = crate::input::map(input, "memory")?;
        match method.get() {
            0 => self.store_or_commit(&m, Tier::Working, ctx).await,
            1 => self.recall_from_input(&m).await,
            2 => self.forget_from_input(&m).await,
            3 => {
                let tier = tier_from_input(&m)?;
                self.store_or_commit(&m, tier, ctx).await
            }
            4 => self.consolidate_from_input(&m, ctx).await,
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

impl MemoryDriver {
    async fn store_or_commit(
        &self,
        input: &BTreeMap<String, Value>,
        tier: Tier,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        let id = id_from_input(input, &owner, &namespace, ctx)?;
        let path = memory_path(&owner, &namespace, &id)?;
        let mut entry = build_entry(&owner, &namespace, &id, tier, input, ctx)?;
        self.write_indexed_entry(&path, &mut entry, ctx).await?;
        Ok(Outcome::Done(store_result(&id, &path, true)))
    }

    async fn write_indexed_entry(
        &self,
        path: &Path,
        entry: &mut Value,
        ctx: &DriverContext,
    ) -> Result<(), DriverError> {
        self.stamp_and_index(path, entry).await?;
        match self
            .state
            .write_cas_tainted(path, None, entry.clone(), ctx.taint.clone())
            .await
        {
            Ok(()) => Ok(()),
            Err(StateError::CasFailed { actual, .. }) => {
                let actual = actual.map(|value| *value);
                match actual {
                    Some(actual) if actual == *entry => Ok(()),
                    Some(actual) => {
                        self.reindex_existing(&actual).await.map_err(|restore| {
                            DriverError::Other(format!(
                                "memory id conflict and index restore failed: {restore}"
                            ))
                        })?;
                        Err(DriverError::InvalidInput(format!(
                            "memory entry already exists at {path}"
                        )))
                    }
                    None => {
                        let rollback = self.delete_index_for_entry(entry).await;
                        Err(match rollback {
                            Ok(()) => DriverError::Other(format!(
                                "state CAS failed at {path} with no actual value"
                            )),
                            Err(error) => DriverError::Other(format!(
                                "state CAS failed at {path}; index rollback failed: {error}"
                            )),
                        })
                    }
                }
            }
            Err(error) => {
                let rollback = self.delete_index_for_entry(entry).await;
                Err(match rollback {
                    Ok(()) => DriverError::Other(error.to_string()),
                    Err(rollback) => DriverError::Other(format!(
                        "state write failed: {error}; index rollback failed: {rollback}"
                    )),
                })
            }
        }
    }

    async fn recall_from_input(
        &self,
        input: &BTreeMap<String, Value>,
    ) -> Result<Outcome, DriverError> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        let query = required_string(input, "query")?;
        let k = optional_nonnegative_usize(input, "k", 5)?;
        let kind = optional_segment(input, "kind")?;
        if k == 0 {
            return Ok(Outcome::Done(Value::List(Vec::new())));
        }
        let recalled = self
            .recall(&owner, &namespace, kind.as_deref(), query, k)
            .await?;
        Ok(Outcome::Done(Value::List(recalled)))
    }

    async fn recall(
        &self,
        owner: &str,
        namespace: &str,
        kind: Option<&str>,
        query: &str,
        k: usize,
    ) -> Result<Vec<Value>, DriverError> {
        let query_embedding = self.embed_for_index(&Value::Str(query.to_string())).await?;
        let index_space = Self::index_space(owner, namespace, &query_embedding.space_id);
        let mut search = BTreeMap::new();
        search.insert("space_id".into(), Value::Str(index_space));
        search.insert("query_vec".into(), query_embedding.vector);
        search.insert("k".into(), Value::Int(overfetch(k) as i64));
        let index_ctx = internal_ctx();
        let hits = match self
            .index
            .call(
                MethodId::new(1),
                Value::Map(search),
                OutputMode::Unary,
                &index_ctx,
            )
            .await?
        {
            Outcome::Done(Value::List(hits)) => hits,
            other => {
                return Err(DriverError::Other(format!(
                    "index search returned unexpected outcome: {other:?}"
                )));
            }
        };

        let mut by_id = BTreeMap::new();
        let mut signals = Vec::new();
        for hit in &hits {
            let hm = hit
                .as_map()
                .ok_or_else(|| DriverError::Other("index hit must be a map".into()))?;
            let id = hm
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DriverError::Other("index hit missing id".into()))?;
            let sim = match hm.get("sim") {
                Some(Value::Float(FloatBits(f))) => *f,
                Some(Value::Int(i)) => *i as f64,
                _ => return Err(DriverError::Other("index hit missing numeric sim".into())),
            };
            let path = memory_path(owner, namespace, id)?;
            let entry = self
                .state
                .read(&path)
                .await
                .map_err(|e| DriverError::Other(e.to_string()))?
                .ok_or_else(|| {
                    DriverError::Other(format!("index hit {id:?} has no state entry at {path}"))
                })?;
            validate_stored_entry(&path, owner, namespace, &entry)?;
            if let Some(kind_filter) = kind
                && entry_kind(&entry) != Some(kind_filter)
            {
                continue;
            }
            let mut signal = BTreeMap::new();
            signal.insert("id".into(), Value::Str(id.to_string()));
            signal.insert("semantic_sim".into(), Value::Float(FloatBits(sim)));
            signal.insert("recency".into(), Value::Float(FloatBits(0.0)));
            if let Some(weight) = entry_field(&entry, "weight") {
                signal.insert("weight".into(), weight.clone());
            }
            if let Some(confidence) = entry_field(&entry, "confidence") {
                signal.insert("confidence".into(), confidence.clone());
            }
            signals.push(Value::Map(signal));
            by_id.insert(id.to_string(), entry);
        }

        if signals.is_empty() {
            return Ok(Vec::new());
        }

        let mut rank_in = BTreeMap::new();
        rank_in.insert("signals".into(), Value::List(signals));
        let rank_ctx = internal_ctx();
        let ranked = match self
            .ranker
            .call(
                MethodId::new(0),
                Value::Map(rank_in),
                OutputMode::Unary,
                &rank_ctx,
            )
            .await?
        {
            Outcome::Done(Value::List(ranked)) => ranked,
            other => {
                return Err(DriverError::Other(format!(
                    "rank score returned unexpected outcome: {other:?}"
                )));
            }
        };

        let mut out = Vec::with_capacity(k);
        for ranked_entry in ranked {
            if out.len() >= k {
                break;
            }
            let Some(id) = ranked_entry
                .as_map()
                .and_then(|m| m.get("id"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            if let Some(entry) = by_id.remove(id) {
                out.push(entry);
            }
        }
        Ok(out)
    }

    async fn forget_from_input(
        &self,
        input: &BTreeMap<String, Value>,
    ) -> Result<Outcome, DriverError> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        if optional_bool(input, "confirm_all", false)? {
            let entries = self.load_namespace_entries(&owner, &namespace).await?;
            for (_, entry) in &entries {
                self.delete_entry_with_index(entry).await?;
            }
            return Ok(Outcome::Done(Value::Int(entries.len() as i64)));
        }

        let id = required_segment(input, "id")?;
        let path = memory_path(&owner, &namespace, &id)?;
        let Some(entry) = self
            .state
            .read(&path)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
        else {
            return Ok(Outcome::Done(Value::Bool(false)));
        };
        self.delete_entry_with_index(&entry).await?;
        Ok(Outcome::Done(Value::Bool(true)))
    }

    async fn delete_entry_with_index(&self, entry: &Value) -> Result<(), DriverError> {
        let path = entry_path(entry)?;
        self.delete_index_for_entry(entry).await?;
        match self.state.write_delete(&path).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let restore = self.reindex_existing(entry).await;
                Err(match restore {
                    Ok(()) => DriverError::Other(error.to_string()),
                    Err(restore) => DriverError::Other(format!(
                        "state delete failed: {error}; index restore failed: {restore}"
                    )),
                })
            }
        }
    }

    async fn consolidate_from_input(
        &self,
        input: &BTreeMap<String, Value>,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        let entries = self.load_namespace_entries(&owner, &namespace).await?;
        let summaries = consolidate(&entries, &owner, &namespace, ctx)?;
        let count = summaries.len();
        for (path, mut summary) in summaries {
            self.write_indexed_entry(&path, &mut summary, ctx).await?;
        }
        Ok(Outcome::Done(Value::Int(count as i64)))
    }

    async fn load_namespace_entries(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<Vec<(Path, Value)>, DriverError> {
        let root = namespace_path(owner, namespace)?;
        let entries = self
            .state
            .read_prefix(&root)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        for (path, entry) in &entries {
            validate_stored_entry(path, owner, namespace, entry)?;
        }
        Ok(entries)
    }

    async fn stamp_and_index(&self, path: &Path, entry: &mut Value) -> Result<(), DriverError> {
        let owner = entry_required_str(entry, "owner")?.to_string();
        let namespace = entry_required_str(entry, "namespace")?.to_string();
        let id = entry_required_str(entry, "id")?.to_string();
        let payload = index_payload(entry);
        let embedding = self.embed_for_index(&payload).await?;
        let index_space = Self::index_space(&owner, &namespace, &embedding.space_id);
        let index_text = entry_text(entry);
        let mut index_meta = BTreeMap::new();
        index_meta.insert("id".into(), Value::Str(id.clone()));
        index_meta.insert("path".into(), Value::Str(path.to_string()));
        index_meta.insert("space_id".into(), Value::Str(index_space.clone()));
        index_meta.insert(
            "embedding_space".into(),
            Value::Str(embedding.space_id.clone()),
        );
        if !index_text.is_empty() {
            index_meta.insert("text".into(), Value::Str(index_text));
        }
        if let Some(model) = &embedding.embedding_model {
            index_meta.insert("embedding_model".into(), Value::Str(model.clone()));
        }
        if let Some(tensor) = &embedding.tensor {
            index_meta.insert("embedding".into(), tensor.clone());
        }
        let map = entry_map_mut(entry)?;
        map.insert("index".into(), Value::Map(index_meta));

        let mut upsert = BTreeMap::new();
        upsert.insert("space_id".into(), Value::Str(index_space));
        upsert.insert("id".into(), Value::Str(id));
        upsert.insert("vector".into(), embedding.vector);
        let index_ctx = internal_ctx();
        match self
            .index
            .call(
                MethodId::new(0),
                Value::Map(upsert),
                OutputMode::Unary,
                &index_ctx,
            )
            .await?
        {
            Outcome::Done(Value::Bool(true)) => Ok(()),
            other => Err(DriverError::Other(format!(
                "index upsert returned unexpected outcome: {other:?}"
            ))),
        }
    }

    async fn delete_index_for_entry(&self, entry: &Value) -> Result<(), DriverError> {
        let indexed = indexed_entry(entry)?;
        let mut delete = BTreeMap::new();
        delete.insert("space_id".into(), Value::Str(indexed.space_id));
        delete.insert("id".into(), Value::Str(indexed.id));
        let index_ctx = internal_ctx();
        match self
            .index
            .call(
                MethodId::new(2),
                Value::Map(delete),
                OutputMode::Unary,
                &index_ctx,
            )
            .await?
        {
            Outcome::Done(Value::Bool(true)) => Ok(()),
            other => Err(DriverError::Other(format!(
                "index delete returned unexpected outcome: {other:?}"
            ))),
        }
    }

    async fn reindex_existing(&self, entry: &Value) -> Result<(), DriverError> {
        let path = entry_path(entry)?;
        let mut restored = entry.clone();
        self.stamp_and_index(&path, &mut restored).await
    }
}

fn build_entry(
    owner: &str,
    namespace: &str,
    id: &str,
    tier: Tier,
    input: &BTreeMap<String, Value>,
    ctx: &DriverContext,
) -> Result<Value, DriverError> {
    let content = input
        .get("content")
        .or_else(|| input.get("entry"))
        .cloned()
        .ok_or_else(|| {
            DriverError::InvalidInput("memory store requires `content` or `entry`".into())
        })?;
    let kind = optional_segment(input, "kind")?.unwrap_or_else(|| {
        if namespace == SKILLS_NAMESPACE {
            "method".to_string()
        } else {
            "fact".to_string()
        }
    });
    let mut facets = optional_map(input, "facets")?.cloned().unwrap_or_default();
    for key in ["trigger_hint", "tags", "media", "procedure_ref"] {
        if let Some(value) = input.get(key)
            && !facets.contains_key(key)
        {
            facets.insert(key.to_string(), value.clone());
        }
    }
    let low_trust = ctx.taint.has_untrusted_content() || optional_bool(input, "low_trust", false)?;
    let mut entry = BTreeMap::new();
    entry.insert("id".into(), Value::Str(id.to_string()));
    entry.insert("owner".into(), Value::Str(owner.to_string()));
    entry.insert("namespace".into(), Value::Str(namespace.to_string()));
    entry.insert("kind".into(), Value::Str(kind));
    entry.insert("content".into(), content);
    entry.insert("facets".into(), Value::Map(facets));
    entry.insert("tier".into(), Value::Str(tier.as_str().to_string()));
    entry.insert(
        "weight".into(),
        Value::Float(FloatBits(optional_f64(input, "weight", 1.0)?)),
    );
    entry.insert(
        "confidence".into(),
        Value::Float(FloatBits(optional_f64(input, "confidence", 1.0)?)),
    );
    entry.insert("access_count".into(), Value::Int(0));
    entry.insert("low_trust".into(), Value::Bool(low_trust));
    entry.insert(
        "links".into(),
        Value::Map(optional_map(input, "links")?.cloned().unwrap_or_default()),
    );
    entry.insert(
        "provenance".into(),
        input.get("provenance").cloned().unwrap_or(Value::Null),
    );
    entry.insert("version".into(), Value::Int(1));
    Ok(Value::Map(entry))
}

fn consolidate(
    entries: &[(Path, Value)],
    owner: &str,
    namespace: &str,
    ctx: &DriverContext,
) -> Result<Vec<(Path, Value)>, DriverError> {
    const THRESHOLD: f64 = 0.34;
    let candidates: Vec<&Value> = entries
        .iter()
        .map(|(_, entry)| entry)
        .filter(|entry| {
            matches!(
                entry_field(entry, "tier").and_then(Value::as_str),
                Some("working" | "recent")
            )
        })
        .collect();
    let texts: Vec<String> = candidates.iter().map(|entry| entry_text(entry)).collect();
    let mut used = vec![false; texts.len()];
    let mut summaries = Vec::new();
    for i in 0..texts.len() {
        if used[i] || texts[i].is_empty() {
            continue;
        }
        let mut cluster_texts = vec![texts[i].clone()];
        let mut source_ids = vec![entry_required_str(candidates[i], "id")?.to_string()];
        let mut low_trust = entry_required_bool(candidates[i], "low_trust")?;
        used[i] = true;
        for j in (i + 1)..texts.len() {
            if !used[j] && overlap(&texts[i], &texts[j]) >= THRESHOLD {
                cluster_texts.push(texts[j].clone());
                source_ids.push(entry_required_str(candidates[j], "id")?.to_string());
                low_trust |= entry_required_bool(candidates[j], "low_trust")?;
                used[j] = true;
            }
        }
        if cluster_texts.len() < 2 {
            continue;
        }
        let summary = format!("[consolidated] {}", cluster_texts.join(" | "));
        let id = summary_id(owner, namespace, &source_ids, ctx)?;
        let path = memory_path(owner, namespace, &id)?;
        let mut input = BTreeMap::new();
        input.insert("content".into(), Value::Str(summary));
        input.insert("kind".into(), Value::Str("summary".into()));
        input.insert("weight".into(), Value::Float(FloatBits(1.5)));
        input.insert("confidence".into(), Value::Float(FloatBits(1.0)));
        input.insert("low_trust".into(), Value::Bool(low_trust));
        let mut facets = BTreeMap::new();
        facets.insert(
            "consolidated_count".into(),
            Value::Int(cluster_texts.len() as i64),
        );
        input.insert("facets".into(), Value::Map(facets));
        let mut links = BTreeMap::new();
        links.insert(
            "derived_from".into(),
            Value::List(source_ids.into_iter().map(Value::Str).collect()),
        );
        input.insert("links".into(), Value::Map(links));
        summaries.push((
            path,
            build_entry(owner, namespace, &id, Tier::LongTerm, &input, ctx)?,
        ));
    }
    Ok(summaries)
}

fn namespace_from_input(input: &BTreeMap<String, Value>) -> Result<String, DriverError> {
    optional_segment(input, "namespace")
        .map(|namespace| namespace.unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()))
}

fn id_from_input(
    input: &BTreeMap<String, Value>,
    owner: &str,
    namespace: &str,
    ctx: &DriverContext,
) -> Result<String, DriverError> {
    if let Some(id) = optional_segment(input, "id")? {
        return Ok(id);
    }
    if namespace == SKILLS_NAMESPACE
        && let Some(name) = optional_segment(input, "name")?
    {
        return Ok(name);
    }
    let op_id = ctx.operation_id.ok_or_else(|| {
        DriverError::InvalidInput("memory store requires id or OperationId".into())
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(owner.as_bytes());
    hasher.update(namespace.as_bytes());
    hash_operation_id(&mut hasher, op_id);
    Ok(format!("op-{}", hasher.finalize().to_hex()))
}

fn summary_id(
    owner: &str,
    namespace: &str,
    source_ids: &[String],
    ctx: &DriverContext,
) -> Result<String, DriverError> {
    let op_id = ctx.operation_id.ok_or_else(|| {
        DriverError::InvalidInput("memory consolidate requires OperationId".into())
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(owner.as_bytes());
    hasher.update(namespace.as_bytes());
    hash_operation_id(&mut hasher, op_id);
    for source in source_ids {
        hasher.update(source.as_bytes());
    }
    Ok(format!("summary-{}", hasher.finalize().to_hex()))
}

fn tier_from_input(input: &BTreeMap<String, Value>) -> Result<Tier, DriverError> {
    match input.get("tier").and_then(|v| v.as_str()) {
        Some("working") | None => Ok(Tier::Working),
        Some("recent") => Ok(Tier::Recent),
        Some("long_term") => Ok(Tier::LongTerm),
        Some("archive") => Ok(Tier::Archive),
        Some(other) => Err(DriverError::InvalidInput(format!(
            "unknown memory tier {other:?}"
        ))),
    }
}

fn memory_path(owner: &str, namespace: &str, id: &str) -> Result<Path, DriverError> {
    namespace_path(owner, namespace)?
        .try_push_literal(id)
        .map_err(|e| DriverError::InvalidInput(format!("invalid memory id {id:?}: {e}")))
}

fn namespace_path(owner: &str, namespace: &str) -> Result<Path, DriverError> {
    Path::try_new("state")
        .and_then(|path| path.try_push("memory"))
        .and_then(|path| path.try_push_literal(owner))
        .and_then(|path| path.try_push_literal(namespace))
        .map_err(|e| {
            DriverError::InvalidInput(format!(
                "invalid memory owner/namespace {owner:?}/{namespace:?}: {e}"
            ))
        })
}

fn required_segment(
    input: &BTreeMap<String, Value>,
    field: &'static str,
) -> Result<String, DriverError> {
    let value = required_string(input, field)?;
    validate_segment(field, value)
}

fn optional_segment(
    input: &BTreeMap<String, Value>,
    field: &'static str,
) -> Result<Option<String>, DriverError> {
    optional_string(input, field).and_then(|value| match value {
        Some(value) => validate_segment(field, value).map(Some),
        None => Ok(None),
    })
}

fn validate_segment(field: &'static str, value: &str) -> Result<String, DriverError> {
    Path::try_new("state")
        .and_then(|path| path.try_push_literal(value))
        .map_err(|e| DriverError::InvalidInput(format!("{field} is not a safe segment: {e}")))?;
    Ok(value.to_string())
}

fn required_string<'a>(
    input: &'a BTreeMap<String, Value>,
    field: &'static str,
) -> Result<&'a str, DriverError> {
    optional_string(input, field)?.ok_or_else(|| {
        DriverError::InvalidInput(format!("memory input missing required field {field}"))
    })
}

fn optional_string<'a>(
    input: &'a BTreeMap<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, DriverError> {
    match input.get(field) {
        Some(Value::Str(value)) if !value.is_empty() => Ok(Some(value.as_str())),
        Some(Value::Str(_)) => Err(DriverError::InvalidInput(format!(
            "{field} must not be empty"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{field} must be a string"
        ))),
        None => Ok(None),
    }
}

fn optional_map<'a>(
    input: &'a BTreeMap<String, Value>,
    field: &'static str,
) -> Result<Option<&'a BTreeMap<String, Value>>, DriverError> {
    match input.get(field) {
        Some(Value::Map(map)) => Ok(Some(map)),
        Some(_) => Err(DriverError::InvalidInput(format!("{field} must be a map"))),
        None => Ok(None),
    }
}

fn optional_bool(
    input: &BTreeMap<String, Value>,
    field: &'static str,
    default: bool,
) -> Result<bool, DriverError> {
    match input.get(field) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(DriverError::InvalidInput(format!("{field} must be a bool"))),
        None => Ok(default),
    }
}

fn optional_f64(
    input: &BTreeMap<String, Value>,
    field: &'static str,
    default: f64,
) -> Result<f64, DriverError> {
    match input.get(field) {
        Some(Value::Float(FloatBits(value))) if value.is_finite() => Ok(*value),
        Some(Value::Int(value)) => Ok(*value as f64),
        Some(Value::Float(_)) => Err(DriverError::InvalidInput(format!("{field} must be finite"))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{field} must be numeric"
        ))),
        None => Ok(default),
    }
}

fn optional_nonnegative_usize(
    input: &BTreeMap<String, Value>,
    field: &'static str,
    default: usize,
) -> Result<usize, DriverError> {
    match input.get(field) {
        Some(Value::Int(value)) if *value >= 0 => usize::try_from(*value).map_err(|_error| {
            DriverError::InvalidInput(format!("{field} is too large for this platform"))
        }),
        Some(Value::Int(_)) => Err(DriverError::InvalidInput(format!(
            "{field} must be nonnegative"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{field} must be an integer"
        ))),
        None => Ok(default),
    }
}

fn validate_stored_entry(
    path: &Path,
    owner: &str,
    namespace: &str,
    entry: &Value,
) -> Result<(), DriverError> {
    let entry_owner = entry_required_str(entry, "owner")?;
    let entry_namespace = entry_required_str(entry, "namespace")?;
    let id = entry_required_str(entry, "id")?;
    if entry_owner != owner || entry_namespace != namespace {
        return Err(DriverError::Other(format!(
            "memory entry identity mismatch at {path}"
        )));
    }
    let expected_path = memory_path(entry_owner, entry_namespace, id)?;
    if &expected_path != path {
        return Err(DriverError::Other(format!(
            "memory entry path mismatch at {path}"
        )));
    }
    entry_required_str(entry, "kind")?;
    validate_stored_tier(entry_required_str(entry, "tier")?)?;
    entry_required_field(entry, "content")?;
    entry_required_map(entry, "facets")?;
    entry_required_number(entry, "weight")?;
    entry_required_number(entry, "confidence")?;
    entry_required_int(entry, "access_count")?;
    entry_required_bool(entry, "low_trust")?;
    entry_required_map(entry, "links")?;
    entry_required_field(entry, "provenance")?;
    entry_required_int(entry, "version")?;
    let indexed = indexed_entry(entry)?;
    if indexed.id != id {
        return Err(DriverError::Other(format!(
            "memory index metadata id mismatch at {path}"
        )));
    }
    Ok(())
}

fn entry_map(entry: &Value) -> Result<&BTreeMap<String, Value>, DriverError> {
    entry
        .as_map()
        .ok_or_else(|| DriverError::Other("memory entry must be a map".into()))
}

fn entry_map_mut(entry: &mut Value) -> Result<&mut BTreeMap<String, Value>, DriverError> {
    match entry {
        Value::Map(map) => Ok(map),
        _ => Err(DriverError::Other("memory entry must be a map".into())),
    }
}

fn entry_required_str<'a>(entry: &'a Value, field: &'static str) -> Result<&'a str, DriverError> {
    match entry_map(entry)?.get(field) {
        Some(Value::Str(value)) if !value.is_empty() => Ok(value.as_str()),
        Some(Value::Str(_)) => Err(DriverError::Other(format!(
            "memory entry field {field} must not be empty"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "memory entry field {field} must be string"
        ))),
        None => Err(DriverError::Other(format!("memory entry missing {field}"))),
    }
}

fn entry_required_field<'a>(
    entry: &'a Value,
    field: &'static str,
) -> Result<&'a Value, DriverError> {
    entry_map(entry)?
        .get(field)
        .ok_or_else(|| DriverError::Other(format!("memory entry missing {field}")))
}

fn entry_required_map<'a>(
    entry: &'a Value,
    field: &'static str,
) -> Result<&'a BTreeMap<String, Value>, DriverError> {
    match entry_required_field(entry, field)? {
        Value::Map(map) => Ok(map),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be map"
        ))),
    }
}

fn entry_required_bool(entry: &Value, field: &'static str) -> Result<bool, DriverError> {
    match entry_required_field(entry, field)? {
        Value::Bool(value) => Ok(*value),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be bool"
        ))),
    }
}

fn entry_required_number(entry: &Value, field: &'static str) -> Result<(), DriverError> {
    match entry_required_field(entry, field)? {
        Value::Int(_) => Ok(()),
        Value::Float(FloatBits(value)) if value.is_finite() => Ok(()),
        Value::Float(_) => Err(DriverError::Other(format!(
            "memory entry field {field} must be finite"
        ))),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be numeric"
        ))),
    }
}

fn entry_required_int(entry: &Value, field: &'static str) -> Result<i64, DriverError> {
    match entry_required_field(entry, field)? {
        Value::Int(value) => Ok(*value),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be integer"
        ))),
    }
}

fn validate_stored_tier(tier: &str) -> Result<(), DriverError> {
    match tier {
        "working" | "recent" | "long_term" | "archive" => Ok(()),
        other => Err(DriverError::Other(format!(
            "memory entry has unknown tier {other:?}"
        ))),
    }
}

fn entry_field<'a>(entry: &'a Value, field: &str) -> Option<&'a Value> {
    entry.as_map().and_then(|map| map.get(field))
}

fn entry_kind(entry: &Value) -> Option<&str> {
    entry_field(entry, "kind").and_then(Value::as_str)
}

fn entry_path(entry: &Value) -> Result<Path, DriverError> {
    let owner = entry_required_str(entry, "owner")?;
    let namespace = entry_required_str(entry, "namespace")?;
    let id = entry_required_str(entry, "id")?;
    memory_path(owner, namespace, id)
}

fn indexed_entry(entry: &Value) -> Result<IndexedEntry, DriverError> {
    let index = entry_map(entry)?
        .get("index")
        .and_then(|value| value.as_map())
        .ok_or_else(|| DriverError::Other("memory entry missing index metadata".into()))?;
    let id = index
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| DriverError::Other("memory index metadata missing id".into()))?;
    let space_id = index
        .get("space_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| DriverError::Other("memory index metadata missing space_id".into()))?;
    Ok(IndexedEntry {
        id: id.to_string(),
        space_id: space_id.to_string(),
    })
}

fn store_result(id: &str, path: &Path, indexed: bool) -> Value {
    let mut result = BTreeMap::new();
    result.insert("id".into(), Value::Str(id.to_string()));
    result.insert("path".into(), Value::Str(path.to_string()));
    result.insert("indexed".into(), Value::Bool(indexed));
    Value::Map(result)
}

fn index_payload(entry: &Value) -> Value {
    let text = entry_text(entry);
    if text.is_empty() {
        entry
            .as_map()
            .and_then(|map| map.get("content"))
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Str(text)
    }
}

fn hash_operation_id(hasher: &mut blake3::Hasher, op_id: xolotl_types::OperationId) {
    hasher.update(&op_id.process.get().to_le_bytes());
    hasher.update(&op_id.position.get().to_le_bytes());
    hasher.update(&op_id.attempt.to_le_bytes());
}

fn entry_text(entry: &Value) -> String {
    let mut parts = Vec::new();
    collect_index_text(entry, &mut parts);
    parts.join("\n")
}

fn collect_index_text<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::Str(text) if !text.trim().is_empty() => out.push(text.as_str()),
        Value::List(items) => {
            for item in items {
                collect_index_text(item, out);
            }
        }
        Value::Map(map) => {
            for key in [
                "content",
                "text",
                "knowledge",
                "summary",
                "trigger_hint",
                "title",
                "tags",
            ] {
                if let Some(value) = map.get(key) {
                    collect_index_text(value, out);
                }
            }
            if let Some(Value::Map(facets)) = map.get("facets") {
                for key in ["trigger_hint", "tags", "title", "summary"] {
                    if let Some(value) = facets.get(key) {
                        collect_index_text(value, out);
                    }
                }
            }
        }
        _ => {}
    }
}

fn overlap(query: &str, text: &str) -> f64 {
    let q: BTreeSet<&str> = query.split_whitespace().collect();
    if q.is_empty() {
        return 0.0;
    }
    let t: BTreeSet<&str> = text.split_whitespace().collect();
    let hits = q.iter().filter(|w| t.contains(*w)).count();
    hits as f64 / q.len() as f64
}

fn overfetch(k: usize) -> usize {
    k.saturating_mul(8).max(k)
}

fn internal_ctx() -> DriverContext {
    DriverContext::new(
        xolotl_types::IdentityRef::ROOT,
        xolotl_types::ProcessId::new(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, bail, ensure};
    use xolotl_state::InMemoryBackend;
    use xolotl_types::{IdentityRef, NodeId, OperationId, ProcessId, TaintSet, TaintSource};

    struct BagOfWordsEmbedder;

    #[async_trait]
    impl InferenceBackend for BagOfWordsEmbedder {
        async fn infer(&self, _input: &Value) -> Result<Value, String> {
            Ok(Value::Null)
        }

        async fn embed(&self, input: &Value) -> Result<Value, String> {
            const VOCAB: &[&str] = &[
                "coffee",
                "berlin",
                "morning",
                "likes",
                "lives",
                "every",
                "in",
                "checklist",
                "scraped",
                "poisoned",
                "ritual",
            ];
            let text = match input {
                Value::Str(s) => s.clone(),
                Value::Map(m) => m
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_default(),
                _ => String::new(),
            };
            let words: BTreeSet<&str> = text.split_whitespace().collect();
            let vector: Vec<Value> = VOCAB
                .iter()
                .map(|word| Value::Float(FloatBits(if words.contains(*word) { 1.0 } else { 0.0 })))
                .collect();
            let mut m = BTreeMap::new();
            m.insert("vector".into(), Value::List(vector));
            m.insert("space_id".into(), Value::Str("test-bow".into()));
            Ok(Value::Map(m))
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
                Value::List(vec![Value::Float(FloatBits(1.0)); 11]),
            );
            m.insert("space_id".into(), Value::Str("other-space".into()));
            Ok(Value::Map(m))
        }
    }

    fn driver(state: Backend) -> MemoryDriver {
        MemoryDriver::new(state).with_embedder(Arc::new(BagOfWordsEmbedder))
    }

    fn ctx(pos: u32) -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(OperationId::new(ProcessId::new(1), NodeId::new(pos), 0))
    }

    fn tainted_ctx(pos: u32) -> DriverContext {
        ctx(pos).with_taint(TaintSet::of(TaintSource::Fetched {
            host: "evil.example".into(),
        }))
    }

    fn store_input(owner: &str, entry: Value) -> Value {
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str(owner.into()));
        m.insert("entry".into(), entry);
        Value::Map(m)
    }

    fn store_with_id(owner: &str, namespace: &str, id: &str, entry: Value) -> Value {
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str(owner.into()));
        m.insert("namespace".into(), Value::Str(namespace.into()));
        m.insert("id".into(), Value::Str(id.into()));
        m.insert("entry".into(), entry);
        Value::Map(m)
    }

    fn recall_input(owner: &str, namespace: &str, query: &str, k: i64) -> Value {
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str(owner.into()));
        m.insert("namespace".into(), Value::Str(namespace.into()));
        m.insert("query".into(), Value::Str(query.into()));
        m.insert("k".into(), Value::Int(k));
        Value::Map(m)
    }

    fn forget_input(owner: &str, namespace: &str, id: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str(owner.into()));
        m.insert("namespace".into(), Value::Str(namespace.into()));
        m.insert("id".into(), Value::Str(id.into()));
        Value::Map(m)
    }

    fn done_list(outcome: Outcome) -> anyhow::Result<Vec<Value>> {
        match outcome {
            Outcome::Done(Value::List(values)) => Ok(values),
            other => bail!("expected list outcome, got {other:?}"),
        }
    }

    fn done_map(outcome: Outcome) -> anyhow::Result<BTreeMap<String, Value>> {
        match outcome {
            Outcome::Done(Value::Map(values)) => Ok(values),
            other => bail!("expected map outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_rejects_missing_content() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        let mut input = BTreeMap::new();
        input.insert("owner".into(), Value::Str("alice".into()));
        let out = d
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(1),
            )
            .await;
        ensure!(out.is_err(), "memory store accepted missing content");
        Ok(())
    }

    #[tokio::test]
    async fn store_then_recall_ranks_by_overlap() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        for (idx, text) in ["likes coffee", "lives in berlin", "coffee every morning"]
            .into_iter()
            .enumerate()
        {
            d.call(
                MethodId::new(0),
                store_input("alice", Value::Str(text.into())),
                OutputMode::Unary,
                &ctx(idx as u32 + 1),
            )
            .await
            .map_err(anyhow::Error::msg)?;
        }
        let top = done_list(
            d.call(
                MethodId::new(1),
                recall_input("alice", DEFAULT_NAMESPACE, "coffee", 2),
                OutputMode::Unary,
                &ctx(10),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(top.len() == 2, "recall result count: {}", top.len());
        ensure!(
            top.iter().all(|entry| entry_text(entry).contains("coffee")),
            "recall results must all mention coffee"
        );
        Ok(())
    }

    #[tokio::test]
    async fn namespace_isolates_skill_entries() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        d.call(
            MethodId::new(0),
            store_with_id(
                "alice",
                DEFAULT_NAMESPACE,
                "fact-coffee",
                Value::Str("likes coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await
        .map_err(anyhow::Error::msg)?;
        let mut skill = BTreeMap::new();
        skill.insert("owner".into(), Value::Str("alice".into()));
        skill.insert("namespace".into(), Value::Str(SKILLS_NAMESPACE.into()));
        skill.insert("name".into(), Value::Str("coffee-checklist".into()));
        skill.insert("content".into(), Value::Str("coffee checklist".into()));
        skill.insert("trigger_hint".into(), Value::Str("coffee".into()));
        d.call(
            MethodId::new(0),
            Value::Map(skill),
            OutputMode::Unary,
            &ctx(2),
        )
        .await
        .map_err(anyhow::Error::msg)?;

        let general = done_list(
            d.call(
                MethodId::new(1),
                recall_input("alice", DEFAULT_NAMESPACE, "coffee", 5),
                OutputMode::Unary,
                &ctx(3),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(
            general.iter().all(|entry| {
                entry
                    .as_map()
                    .and_then(|m| m.get("namespace"))
                    .and_then(Value::as_str)
                    == Some(DEFAULT_NAMESPACE)
            }),
            "general recall leaked non-general namespace"
        );

        let skills = done_list(
            d.call(
                MethodId::new(1),
                recall_input("alice", SKILLS_NAMESPACE, "coffee", 5),
                OutputMode::Unary,
                &ctx(4),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(
            skills.len() == 1,
            "skill recall result count: {}",
            skills.len()
        );
        ensure!(
            skills[0]
                .as_map()
                .and_then(|m| m.get("id"))
                .and_then(Value::as_str)
                == Some("coffee-checklist"),
            "unexpected skill id: {:?}",
            skills[0].as_map().and_then(|m| m.get("id"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn store_preserves_mixed_content_value() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        let content = Value::Map(BTreeMap::from([
            ("text".into(), Value::Str("coffee ritual".into())),
            (
                "steps".into(),
                Value::List(vec![Value::Str("grind".into()), Value::Str("brew".into())]),
            ),
        ]));
        d.call(
            MethodId::new(0),
            store_with_id("alice", DEFAULT_NAMESPACE, "ritual", content.clone()),
            OutputMode::Unary,
            &ctx(1),
        )
        .await
        .map_err(anyhow::Error::msg)?;
        let recalled = done_list(
            d.call(
                MethodId::new(1),
                recall_input("alice", DEFAULT_NAMESPACE, "coffee", 1),
                OutputMode::Unary,
                &ctx(2),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(
            recalled
                .first()
                .and_then(Value::as_map)
                .and_then(|m| m.get("content"))
                == Some(&content),
            "mixed content was not preserved"
        );
        Ok(())
    }

    #[tokio::test]
    async fn operation_id_derives_stable_store_id() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        let first = done_map(
            d.call(
                MethodId::new(0),
                store_input("alice", Value::Str("likes coffee".into())),
                OutputMode::Unary,
                &ctx(7),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        let second = done_map(
            d.call(
                MethodId::new(0),
                store_input("alice", Value::Str("likes coffee".into())),
                OutputMode::Unary,
                &ctx(7),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(
            first.get("id") == second.get("id"),
            "derived ids differ: {:?} != {:?}",
            first.get("id"),
            second.get("id")
        );
        ensure!(
            first.get("path") == second.get("path"),
            "derived paths differ: {:?} != {:?}",
            first.get("path"),
            second.get("path")
        );
        Ok(())
    }

    #[tokio::test]
    async fn same_id_different_content_is_rejected() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        d.call(
            MethodId::new(0),
            store_with_id(
                "alice",
                DEFAULT_NAMESPACE,
                "stable",
                Value::Str("likes coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await
        .map_err(anyhow::Error::msg)?;
        let err = d
            .call(
                MethodId::new(0),
                store_with_id(
                    "alice",
                    DEFAULT_NAMESPACE,
                    "stable",
                    Value::Str("lives in berlin".into()),
                ),
                OutputMode::Unary,
                &ctx(2),
            )
            .await;
        ensure!(err.is_err(), "same id with different content must fail");
        Ok(())
    }

    #[tokio::test]
    async fn forget_deletes_state_and_index_for_one_entry() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let index = Arc::new(IndexDriver::new());
        let rank = Arc::new(RankerDriver::new());
        let d = MemoryDriver::new(state)
            .with_retrieval_stack(index.clone(), rank)
            .with_embedder(Arc::new(BagOfWordsEmbedder));
        d.call(
            MethodId::new(0),
            store_with_id(
                "bob",
                DEFAULT_NAMESPACE,
                "coffee",
                Value::Str("coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await
        .map_err(anyhow::Error::msg)?;
        d.call(
            MethodId::new(2),
            forget_input("bob", DEFAULT_NAMESPACE, "coffee"),
            OutputMode::Unary,
            &ctx(2),
        )
        .await
        .map_err(anyhow::Error::msg)?;

        let mut q = BTreeMap::new();
        q.insert(
            "space_id".into(),
            Value::Str("memory/bob/general/test-bow".into()),
        );
        q.insert(
            "query_vec".into(),
            Value::List(vec![Value::Float(FloatBits(1.0)); 11]),
        );
        let search = index
            .call(MethodId::new(1), Value::Map(q), OutputMode::Unary, &ctx(3))
            .await;
        ensure!(search.is_err(), "forgotten entry should not remain indexed");
        Ok(())
    }

    #[tokio::test]
    async fn store_derives_low_trust_from_operation_taint() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        d.call(
            MethodId::new(0),
            store_input("dave", Value::Str("scraped from a webpage".into())),
            OutputMode::Unary,
            &tainted_ctx(1),
        )
        .await
        .map_err(anyhow::Error::msg)?;
        let top = done_list(
            d.call(
                MethodId::new(1),
                recall_input("dave", DEFAULT_NAMESPACE, "scraped", 1),
                OutputMode::Unary,
                &ctx(2),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(
            top[0]
                .as_map()
                .and_then(|map| map.get("low_trust"))
                .and_then(Value::as_bool)
                == Some(true),
            "stored memory did not derive low_trust"
        );
        Ok(())
    }

    #[tokio::test]
    async fn commit_tags_low_trust_for_poison_defense() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        let mut m = BTreeMap::new();
        m.insert("owner".into(), Value::Str("carol".into()));
        m.insert("entry".into(), Value::Str("possibly poisoned".into()));
        m.insert("tier".into(), Value::Str("recent".into()));
        m.insert("low_trust".into(), Value::Bool(true));
        d.call(MethodId::new(3), Value::Map(m), OutputMode::Unary, &ctx(1))
            .await
            .map_err(anyhow::Error::msg)?;
        let top = done_list(
            d.call(
                MethodId::new(1),
                recall_input("carol", DEFAULT_NAMESPACE, "poisoned", 1),
                OutputMode::Unary,
                &ctx(2),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(
            top[0]
                .as_map()
                .and_then(|map| map.get("low_trust"))
                .and_then(Value::as_bool)
                == Some(true),
            "committed memory did not preserve low_trust"
        );
        ensure!(
            top[0]
                .as_map()
                .and_then(|map| map.get("tier"))
                .and_then(Value::as_str)
                == Some("recent"),
            "committed memory tier mismatch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn malformed_persisted_memory_entries_fail_closed() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state.clone());
        d.call(
            MethodId::new(0),
            store_with_id(
                "alice",
                DEFAULT_NAMESPACE,
                "bad",
                Value::Str("coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await
        .map_err(anyhow::Error::msg)?;

        let path = memory_path("alice", DEFAULT_NAMESPACE, "bad").map_err(anyhow::Error::msg)?;
        let mut entry = state
            .read(&path)
            .await?
            .context("stored memory entry should exist")?;
        let Value::Map(map) = &mut entry else {
            bail!("stored memory entry was not a map");
        };
        map.remove("low_trust");
        state.write_set(&path, entry).await?;

        let consolidate = d
            .call(
                MethodId::new(4),
                Value::Map(BTreeMap::from([(
                    "owner".into(),
                    Value::Str("alice".into()),
                )])),
                OutputMode::Unary,
                &ctx(2),
            )
            .await;
        ensure!(
            consolidate.is_err(),
            "consolidate should reject malformed persisted memory"
        );

        let recall = d
            .call(
                MethodId::new(1),
                recall_input("alice", DEFAULT_NAMESPACE, "coffee", 1),
                OutputMode::Unary,
                &ctx(3),
            )
            .await;
        ensure!(
            recall.is_err(),
            "recall should reject malformed persisted memory"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recall_rejects_when_query_embedding_space_has_no_index() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let index = Arc::new(IndexDriver::new());
        let rank = Arc::new(RankerDriver::new());
        let d = MemoryDriver::new(state.clone())
            .with_retrieval_stack(index.clone(), rank.clone())
            .with_embedder(Arc::new(BagOfWordsEmbedder));
        d.call(
            MethodId::new(0),
            store_with_id(
                "erin",
                DEFAULT_NAMESPACE,
                "coffee",
                Value::Str("coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await
        .map_err(anyhow::Error::msg)?;

        let d_other = MemoryDriver::new(state)
            .with_retrieval_stack(index, rank)
            .with_embedder(Arc::new(OtherSpaceEmbedder));
        let out = d_other
            .call(
                MethodId::new(1),
                recall_input("erin", DEFAULT_NAMESPACE, "coffee", 1),
                OutputMode::Unary,
                &ctx(2),
            )
            .await;
        ensure!(
            out.is_err(),
            "recall should reject query embeddings in an unindexed space"
        );
        Ok(())
    }

    #[tokio::test]
    async fn consolidate_preserves_low_trust_and_links_sources() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver(state);
        for (idx, (id, text, low_trust)) in [
            ("a", "coffee in the morning", true),
            ("b", "morning coffee ritual", false),
            ("c", "lives in berlin", false),
        ]
        .into_iter()
        .enumerate()
        {
            let mut input =
                match store_with_id("dave", DEFAULT_NAMESPACE, id, Value::Str(text.into())) {
                    Value::Map(map) => map,
                    other => bail!("store helper returned {other:?}"),
                };
            input.insert("low_trust".into(), Value::Bool(low_trust));
            d.call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &ctx(idx as u32 + 1),
            )
            .await
            .map_err(anyhow::Error::msg)?;
        }
        d.call(
            MethodId::new(4),
            Value::Map(BTreeMap::from([(
                "owner".into(),
                Value::Str("dave".into()),
            )])),
            OutputMode::Unary,
            &ctx(20),
        )
        .await
        .map_err(anyhow::Error::msg)?;
        let top = done_list(
            d.call(
                MethodId::new(1),
                recall_input("dave", DEFAULT_NAMESPACE, "coffee morning", 5),
                OutputMode::Unary,
                &ctx(21),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        let summary = top
            .iter()
            .find(|entry| entry_kind(entry) == Some("summary"))
            .context("expected consolidated summary")?;
        ensure!(
            summary
                .as_map()
                .and_then(|map| map.get("low_trust"))
                .and_then(Value::as_bool)
                == Some(true),
            "summary did not preserve low_trust"
        );
        let derived = summary
            .as_map()
            .and_then(|map| map.get("links"))
            .and_then(Value::as_map)
            .and_then(|links| links.get("derived_from"))
            .and_then(|value| match value {
                Value::List(values) => Some(values),
                _ => None,
            })
            .context("summary missing derived_from")?;
        ensure!(
            derived.len() == 2,
            "derived source count: {}",
            derived.len()
        );
        Ok(())
    }
}
