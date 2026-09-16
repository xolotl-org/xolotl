use super::*;
use anyhow::{Context, bail, ensure};
use xolotl_state::InMemoryBackend;
use xolotl_types::{
    BlobRef, DType, ExecutionId, IdentityRef, InvocationId, NodeId, OperationId, ProcessId,
    TaintSet, TaintSource, TensorRef,
};

mod consistency;

fn dense(values: Value) -> Value {
    Value::map(BTreeMap::from([
        ("kind".into(), Value::string("dense".into())),
        ("values".into(), values),
    ]))
}

fn failed(result: &Result<DriverOutput, DriverError>) -> bool {
    matches!(
        result,
        Err(_)
            | Ok(DriverOutput {
                outcome: Outcome::Fail(_),
                ..
            })
    )
}

fn rejection(result: Result<DriverOutput, DriverError>) -> anyhow::Result<String> {
    match result {
        Err(error) => Ok(error.to_string()),
        Ok(DriverOutput {
            outcome: Outcome::Fail(failure),
            ..
        }) => Ok(failure.to_string()),
        Ok(_) => bail!("malformed embedding was accepted"),
    }
}

struct BagOfWordsEmbedder;

#[async_trait]
impl InferenceBackend for BagOfWordsEmbedder {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::null())
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
        let text = match input.view() {
            ValueView::Str(s) => s.to_owned(),
            ValueView::Map(m) => m
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_default(),
            _ => String::new(),
        };
        let words: BTreeSet<&str> = text.split_whitespace().collect();
        let vector: Vec<Value> = VOCAB
            .iter()
            .map(|word| Value::float(FloatBits(if words.contains(*word) { 1.0 } else { 0.0 })))
            .collect();
        let mut m = BTreeMap::new();
        m.insert("representation".into(), dense(Value::list(vector)));
        m.insert("space_id".into(), Value::string("test-bow".into()));
        Ok(Value::map(m))
    }
}

struct OtherSpaceEmbedder;

struct EnvelopeEmbedder(Value);

#[async_trait]
impl InferenceBackend for EnvelopeEmbedder {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::null())
    }

    async fn embed(&self, _input: &Value) -> Result<Value, String> {
        Ok(self.0.clone())
    }
}

struct RemoteEmbedder(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait]
impl InferenceBackend for RemoteEmbedder {
    fn requires_unprotected_input(&self) -> bool {
        true
    }

    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::null())
    }

    async fn embed(&self, input: &Value) -> Result<Value, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        BagOfWordsEmbedder.embed(input).await
    }
}

#[async_trait]
impl InferenceBackend for OtherSpaceEmbedder {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::null())
    }

    async fn embed(&self, _input: &Value) -> Result<Value, String> {
        let mut m = BTreeMap::new();
        m.insert(
            "representation".into(),
            dense(Value::list(vec![Value::float(FloatBits(1.0)); 11])),
        );
        m.insert("space_id".into(), Value::string("other-space".into()));
        Ok(Value::map(m))
    }
}

fn driver(state: Backend) -> MemoryDriver {
    MemoryDriver::new(state).with_embedder(Arc::new(BagOfWordsEmbedder))
}

#[tokio::test]
async fn persisted_provenance_survives_recall_and_consolidation_and_blocks_remote_embedding()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let local = driver(state.clone());
    let protected = TaintSet::of(TaintSource::Protected {
        path: memory_path("private", DEFAULT_NAMESPACE, "a")?,
    });
    let model = TaintSet::of(TaintSource::ModelOutput);
    for (offset, id, text, taint) in [
        (1, "a", "coffee in the morning", protected.clone()),
        (2, "b", "morning coffee ritual", model.clone()),
    ] {
        local
            .call(
                MethodId::new(0),
                store_with_id("private", DEFAULT_NAMESPACE, id, Value::string(text.into())),
                OutputMode::Unary,
                &ctx(offset).with_taint(taint),
            )
            .await?;
    }
    let recall = local
        .call(
            MethodId::new(1),
            recall_input("private", DEFAULT_NAMESPACE, "coffee morning", 5),
            OutputMode::Unary,
            &ctx(3),
        )
        .await?;
    ensure!(recall.taint.has_protected());
    let input = Value::map(BTreeMap::from([(
        "owner".into(),
        Value::string("private".into()),
    )]));
    let output = local
        .call(MethodId::new(4), input.clone(), OutputMode::Unary, &ctx(4))
        .await?;
    ensure!(output.taint.has_protected());
    let (entries, _) = local
        .load_namespace_entries("private", DEFAULT_NAMESPACE)
        .await?;
    let (_, summary) = entries
        .iter()
        .find(|(_, entry)| entry_kind(&entry.value) == Some("summary"))
        .context("missing summary")?;
    let mut expected = protected;
    expected.union(&model);
    ensure!(summary.taint == expected);

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let remote = MemoryDriver::new(state)
        .with_retrieval_stack(local.index.clone(), local.ranker.clone())
        .with_embedder(Arc::new(RemoteEmbedder(calls.clone())));
    ensure!(failed(
        &remote
            .call(MethodId::new(4), input, OutputMode::Unary, &ctx(5))
            .await
    ));
    ensure!(remote.reindex_existing(summary).await?.0);
    ensure!(
        calls.load(std::sync::atomic::Ordering::SeqCst) == 0,
        "protected stored content reached the remote embedder"
    );
    let recalled = remote
        .call(
            MethodId::new(1),
            recall_input("private", DEFAULT_NAMESPACE, "coffee morning", 5),
            OutputMode::Unary,
            &ctx(6),
        )
        .await?;
    ensure!(recalled.taint.has_protected());
    ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 1);
    Ok(())
}

fn ctx(pos: u32) -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_operation_id(OperationId::new(
        ProcessId::new(1),
        ExecutionId::FIRST,
        InvocationId::new(u64::from(pos) + 1),
        NodeId::new(pos),
        0,
    ))
}

fn tainted_ctx(pos: u32) -> DriverContext {
    ctx(pos).with_taint(TaintSet::of(TaintSource::Fetched {
        host: "evil.example".into(),
    }))
}

fn store_input(owner: &str, entry: Value) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::string(owner.into()));
    m.insert("entry".into(), entry);
    Value::map(m)
}

fn store_with_id(owner: &str, namespace: &str, id: &str, entry: Value) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::string(owner.into()));
    m.insert("namespace".into(), Value::string(namespace.into()));
    m.insert("id".into(), Value::string(id.into()));
    m.insert("entry".into(), entry);
    Value::map(m)
}

fn recall_input(owner: &str, namespace: &str, query: &str, k: i64) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::string(owner.into()));
    m.insert("namespace".into(), Value::string(namespace.into()));
    m.insert("query".into(), Value::string(query.into()));
    m.insert("k".into(), Value::integer(k));
    Value::map(m)
}

fn forget_input(owner: &str, namespace: &str, id: &str) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::string(owner.into()));
    m.insert("namespace".into(), Value::string(namespace.into()));
    m.insert("id".into(), Value::string(id.into()));
    Value::map(m)
}

fn done_list(output: DriverOutput) -> anyhow::Result<Vec<Value>> {
    match output.outcome {
        Outcome::Done(value) => Ok(value
            .as_list()
            .context("expected list")?
            .iter()
            .cloned()
            .collect()),
        other => bail!("expected list outcome, got {other:?}"),
    }
}

fn done_map(output: DriverOutput) -> anyhow::Result<ValueMap> {
    match output.outcome {
        Outcome::Done(value) => value.into_map().context("expected map"),
        other => bail!("expected map outcome, got {other:?}"),
    }
}

fn embedding_envelope() -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "representation".into(),
            dense(Value::list(vec![
                Value::float(FloatBits(1.0)),
                Value::float(FloatBits(0.0)),
            ])),
        ),
        ("space_id".into(), Value::string("custom-dense".into())),
        (
            "embedding_model".into(),
            Value::string("custom/model".into()),
        ),
    ])
}

fn tensor_sidecar() -> Value {
    Value::from(TensorRef {
        blob: BlobRef {
            hash: "a".repeat(64),
            size: 8,
            mime: None,
        },
        dtype: DType::F32,
        shape: vec![2],
    })
}

#[tokio::test]
async fn baseline_memory_roundtrips_without_persisting_tensor_artifacts() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let driver = MemoryDriver::new(state.clone());
    driver
        .call(
            MethodId::new(0),
            store_with_id(
                "alice",
                DEFAULT_NAMESPACE,
                "baseline",
                Value::string("baseline memory".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    let stored = state
        .read(&memory_path("alice", DEFAULT_NAMESPACE, "baseline")?)
        .await?
        .context("baseline memory entry missing")?;
    let index = entry_field(&stored, "index")
        .and_then(Value::as_map)
        .context("baseline index metadata missing")?;
    ensure!(
        index.get("embedding").is_none(),
        "baseline persisted a tensor artifact"
    );
    ensure!(
        index.get("embedding_space").and_then(Value::as_str)
            == Some(crate::inference::BASELINE_EMBEDDING_SPACE)
    );
    ensure!(index.get("embedding_model").and_then(Value::as_str) == Some("baseline/blake3-8d"));
    let recalled = done_list(
        driver
            .call(
                MethodId::new(1),
                recall_input("alice", DEFAULT_NAMESPACE, "baseline memory", 1),
                OutputMode::Unary,
                &ctx(2),
            )
            .await?,
    )?;
    ensure!(
        recalled == vec![stored],
        "baseline memory failed to roundtrip"
    );
    Ok(())
}

#[tokio::test]
async fn oversized_recall_limits_return_only_available_entries() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let memory = driver(state.clone());
    memory
        .call(
            MethodId::new(0),
            store_with_id(
                "alice",
                DEFAULT_NAMESPACE,
                "only-entry",
                Value::string("coffee in the morning".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    let stored = state
        .read(&memory_path("alice", DEFAULT_NAMESPACE, "only-entry")?)
        .await?
        .context("stored memory missing")?;
    for k in [i64::from(u32::MAX), 1_i64 << 58, i64::MAX] {
        if usize::try_from(k).is_err() {
            continue;
        }
        let recalled = done_list(
            memory
                .call(
                    MethodId::new(1),
                    recall_input("alice", DEFAULT_NAMESPACE, "coffee morning", k),
                    OutputMode::Unary,
                    &ctx(2),
                )
                .await?,
        )?;
        ensure!(recalled.len() == 1 && recalled[0] == stored);
    }
    Ok(())
}

#[tokio::test]
async fn memory_ignores_embedding_tensor_and_payload_sidecars() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let mut envelope = embedding_envelope();
    envelope.insert("tensor".into(), tensor_sidecar());
    envelope.insert("payload".into(), Value::bytes(vec![0xab; 16 * 1024]));
    let driver = MemoryDriver::new(state.clone())
        .with_embedder(Arc::new(EnvelopeEmbedder(Value::map(envelope))));
    driver
        .call(
            MethodId::new(0),
            store_with_id(
                "alice",
                DEFAULT_NAMESPACE,
                "custom",
                Value::string("custom memory".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    let stored = state
        .read(&memory_path("alice", DEFAULT_NAMESPACE, "custom")?)
        .await?
        .context("custom memory entry missing")?;
    let index = entry_field(&stored, "index")
        .and_then(Value::as_map)
        .context("custom index metadata missing")?;
    for field in ["embedding", "tensor", "payload", "vector"] {
        ensure!(
            index.get(field).is_none(),
            "index metadata retained {field}"
        );
    }
    ensure!(index.get("embedding_space").and_then(Value::as_str) == Some("custom-dense"));
    ensure!(index.get("embedding_model").and_then(Value::as_str) == Some("custom/model"));
    let recalled = done_list(
        driver
            .call(
                MethodId::new(1),
                recall_input("alice", DEFAULT_NAMESPACE, "custom memory", 1),
                OutputMode::Unary,
                &ctx(2),
            )
            .await?,
    )?;
    ensure!(
        recalled == vec![stored],
        "sidecar removal changed dense retrieval"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_embeddings_leave_existing_memory_and_index_unchanged() -> anyhow::Result<()> {
    let mut tensor_only = embedding_envelope();
    tensor_only.insert(
        "representation".into(),
        EmbeddingRepresentation::Tensor(TensorRef {
            blob: BlobRef {
                hash: "a".repeat(64),
                size: 8,
                mime: None,
            },
            dtype: DType::F32,
            shape: vec![2],
        })
        .into_value(),
    );
    let mut cases = vec![("map", Value::null()), ("reader", Value::map(tensor_only))];
    for (field, invalid, expected) in [
        (
            "representation",
            dense(Value::string("not a list".into())),
            "list",
        ),
        ("space_id", Value::string(String::new()), "space_id"),
        ("space_id", Value::integer(1), "space_id"),
        ("embedding_model", Value::integer(1), "embedding_model"),
        ("representation", dense(Value::list(Vec::new())), "empty"),
        (
            "representation",
            dense(Value::list(vec![Value::string("not numeric".into())])),
            "numeric",
        ),
    ] {
        let mut envelope = embedding_envelope();
        envelope.insert(field.into(), invalid);
        cases.push((expected, Value::map(envelope)));
    }

    for (field, malformed) in cases {
        let state = InMemoryBackend::new().into_backend();
        let valid = MemoryDriver::new(state.clone())
            .with_embedder(Arc::new(EnvelopeEmbedder(Value::map(embedding_envelope()))));
        valid
            .call(
                MethodId::new(0),
                store_with_id(
                    "alice",
                    DEFAULT_NAMESPACE,
                    "sentinel",
                    Value::string("preserved memory".into()),
                ),
                OutputMode::Unary,
                &ctx(1),
            )
            .await?;
        let sentinel = memory_path("alice", DEFAULT_NAMESPACE, "sentinel")?;
        let before = state.read_tainted(&sentinel).await?;
        let invalid = MemoryDriver::new(state.clone())
            .with_retrieval_stack(valid.index.clone(), valid.ranker.clone())
            .with_embedder(Arc::new(EnvelopeEmbedder(malformed)));
        let result = invalid
            .call(
                MethodId::new(0),
                store_with_id(
                    "alice",
                    DEFAULT_NAMESPACE,
                    "rejected",
                    Value::string("invalid embedding".into()),
                ),
                OutputMode::Unary,
                &ctx(2),
            )
            .await;
        let error = rejection(result)?;
        ensure!(
            error.to_string().contains(field),
            "malformed {field} did not produce a field-specific error: {error}"
        );
        ensure!(
            state
                .read(&memory_path("alice", DEFAULT_NAMESPACE, "rejected")?)
                .await?
                .is_none(),
            "rejected embedding left a memory entry"
        );
        ensure!(
            state.read_tainted(&sentinel).await? == before,
            "existing memory changed"
        );
        let hits = done_list(
            valid
                .index
                .call(
                    MethodId::new(1),
                    Value::map(BTreeMap::from([
                        (
                            "space_id".into(),
                            Value::string(MemoryDriver::index_space(
                                "alice",
                                DEFAULT_NAMESPACE,
                                "custom-dense",
                            )),
                        ),
                        (
                            "representation".into(),
                            dense(Value::list(vec![Value::integer(1), Value::integer(0)])),
                        ),
                        ("k".into(), Value::integer(10)),
                    ])),
                    OutputMode::Unary,
                    &ctx(3),
                )
                .await?,
        )?;
        ensure!(
            hits.len() == 1,
            "rejected embedding changed indexed entries"
        );
        ensure!(
            hits.first()
                .and_then(Value::as_map)
                .and_then(|entry| entry.get("id"))
                .and_then(Value::as_str)
                == Some("sentinel"),
            "existing index entry was replaced"
        );
    }
    Ok(())
}

#[tokio::test]
async fn store_rejects_missing_content() -> anyhow::Result<()> {
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    let mut input = BTreeMap::new();
    input.insert("owner".into(), Value::string("alice".into()));
    let out = d
        .call(
            MethodId::new(0),
            Value::map(input),
            OutputMode::Unary,
            &ctx(1),
        )
        .await;
    ensure!(out.is_err(), "memory store accepted missing content");
    Ok(())
}

#[tokio::test]
async fn store_then_recall_ranks_by_overlap() -> anyhow::Result<()> {
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    for (idx, text) in ["likes coffee", "lives in berlin", "coffee every morning"]
        .into_iter()
        .enumerate()
    {
        d.call(
            MethodId::new(0),
            store_input("alice", Value::string(text.into())),
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
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    d.call(
        MethodId::new(0),
        store_with_id(
            "alice",
            DEFAULT_NAMESPACE,
            "fact-coffee",
            Value::string("likes coffee".into()),
        ),
        OutputMode::Unary,
        &ctx(1),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let mut skill = BTreeMap::new();
    skill.insert("owner".into(), Value::string("alice".into()));
    skill.insert("namespace".into(), Value::string(SKILLS_NAMESPACE.into()));
    skill.insert("name".into(), Value::string("coffee-checklist".into()));
    skill.insert("content".into(), Value::string("coffee checklist".into()));
    skill.insert("trigger_hint".into(), Value::string("coffee".into()));
    d.call(
        MethodId::new(0),
        Value::map(skill),
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
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    let content = Value::map(BTreeMap::from([
        ("text".into(), Value::string("coffee ritual".into())),
        (
            "steps".into(),
            Value::list(vec![
                Value::string("grind".into()),
                Value::string("brew".into()),
            ]),
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
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    let first = done_map(
        d.call(
            MethodId::new(0),
            store_input("alice", Value::string("likes coffee".into())),
            OutputMode::Unary,
            &ctx(7),
        )
        .await
        .map_err(anyhow::Error::msg)?,
    )?;
    let second = done_map(
        d.call(
            MethodId::new(0),
            store_input("alice", Value::string("likes coffee".into())),
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
    let original = ctx(7).operation_id.context("fixture operation id")?;
    let repeated = OperationId {
        invocation: InvocationId::new(original.invocation.get() + 1),
        ..original
    };
    let independent = OperationId {
        execution: ExecutionId::new(2).context("nonzero scope")?,
        ..original
    };
    let mut ids = BTreeSet::from([first
        .get("id")
        .and_then(Value::as_str)
        .context("stored id")?
        .to_owned()]);
    for operation in [repeated, independent] {
        let stored = done_map(
            d.call(
                MethodId::new(0),
                store_input("alice", Value::string("likes coffee".into())),
                OutputMode::Unary,
                &ctx(7).with_operation_id(operation),
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )?;
        ensure!(
            ids.insert(
                stored
                    .get("id")
                    .and_then(Value::as_str)
                    .context("stored id")?
                    .to_owned()
            ),
            "independent operation overwrote an existing memory entry"
        );
    }
    Ok(())
}

#[tokio::test]
async fn same_id_different_content_is_rejected() -> anyhow::Result<()> {
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    d.call(
        MethodId::new(0),
        store_with_id(
            "alice",
            DEFAULT_NAMESPACE,
            "stable",
            Value::string("likes coffee".into()),
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
                Value::string("lives in berlin".into()),
            ),
            OutputMode::Unary,
            &ctx(2),
        )
        .await;
    ensure!(failed(&err), "same id with different content must fail");
    Ok(())
}

#[tokio::test]
async fn forget_deletes_state_and_index_for_one_entry() -> anyhow::Result<()> {
    let state: Backend = InMemoryBackend::new().into_backend();
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
            Value::string("coffee".into()),
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
        Value::string("memory/bob/general/test-bow".into()),
    );
    q.insert(
        "representation".into(),
        dense(Value::list(vec![Value::float(FloatBits(1.0)); 11])),
    );
    let search = index
        .call(MethodId::new(1), Value::map(q), OutputMode::Unary, &ctx(3))
        .await;
    ensure!(search.is_err(), "forgotten entry should not remain indexed");
    Ok(())
}

#[tokio::test]
async fn store_derives_low_trust_from_operation_taint() -> anyhow::Result<()> {
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    d.call(
        MethodId::new(0),
        store_input("dave", Value::string("scraped from a webpage".into())),
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
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::string("carol".into()));
    m.insert("entry".into(), Value::string("possibly poisoned".into()));
    m.insert("tier".into(), Value::string("recent".into()));
    m.insert("low_trust".into(), Value::boolean(true));
    d.call(MethodId::new(3), Value::map(m), OutputMode::Unary, &ctx(1))
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
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state.clone());
    d.call(
        MethodId::new(0),
        store_with_id(
            "alice",
            DEFAULT_NAMESPACE,
            "bad",
            Value::string("coffee".into()),
        ),
        OutputMode::Unary,
        &ctx(1),
    )
    .await
    .map_err(anyhow::Error::msg)?;

    let path = memory_path("alice", DEFAULT_NAMESPACE, "bad").map_err(anyhow::Error::msg)?;
    let entry = state
        .read(&path)
        .await?
        .context("stored memory entry should exist")?;
    let Some(mut map) = entry.into_map() else {
        bail!("stored memory entry was not a map");
    };
    map.remove("low_trust");
    state.write_set(&path, Value::from(map)).await?;

    let consolidate = d
        .call(
            MethodId::new(4),
            Value::map(BTreeMap::from([(
                "owner".into(),
                Value::string("alice".into()),
            )])),
            OutputMode::Unary,
            &ctx(2),
        )
        .await;
    ensure!(
        failed(&consolidate),
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
        failed(&recall),
        "recall should reject malformed persisted memory"
    );
    Ok(())
}

#[tokio::test]
async fn recall_returns_no_hits_for_an_unindexed_embedding_space() -> anyhow::Result<()> {
    let state: Backend = InMemoryBackend::new().into_backend();
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
            Value::string("coffee".into()),
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
    ensure!(done_list(out?)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn consolidate_preserves_low_trust_and_links_sources() -> anyhow::Result<()> {
    let state: Backend = InMemoryBackend::new().into_backend();
    let d = driver(state);
    for (idx, (id, text, low_trust)) in [
        ("a", "coffee in the morning", true),
        ("b", "morning coffee ritual", false),
        ("c", "lives in berlin", false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = store_with_id("dave", DEFAULT_NAMESPACE, id, Value::string(text.into()))
            .into_map()
            .context("store helper must return a map")?;
        input.insert("low_trust".into(), Value::boolean(low_trust))?;
        d.call(
            MethodId::new(0),
            Value::from(input),
            OutputMode::Unary,
            &ctx(idx as u32 + 1),
        )
        .await
        .map_err(anyhow::Error::msg)?;
    }
    d.call(
        MethodId::new(4),
        Value::map(BTreeMap::from([(
            "owner".into(),
            Value::string("dave".into()),
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
        .and_then(Value::as_list)
        .context("summary missing derived_from")?;
    ensure!(
        derived.len() == 2,
        "derived source count: {}",
        derived.len()
    );
    Ok(())
}
