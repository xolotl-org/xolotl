use super::*;
use std::{
    future::{Future, Ready, ready},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context as TaskContext, Waker},
};
use xolotl_state::{
    StateCursor, StateMutation, StateObservation, StatePage, StateQuery, StateRead, StateResult,
    StateScan, StateWrite,
};

struct ChangingEmbedder(Arc<AtomicUsize>);

#[async_trait]
impl InferenceBackend for ChangingEmbedder {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::null())
    }
    async fn embed(&self, _input: &Value) -> Result<Value, String> {
        let call = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(Embedding {
            space_id: "changing".into(),
            representation: EmbeddingRepresentation::Dense(
                vec![Value::integer(call as i64), Value::integer(1)].into(),
            ),
            embedding_model: None,
        }
        .into_value())
    }
}

fn update(input: Value, generation: &str) -> anyhow::Result<Value> {
    let mut fields = input.into_map().context("update input")?;
    fields.insert(
        "expected_generation".into(),
        Value::string(generation.into()),
    )?;
    Ok(Value::from(fields))
}

fn result_generation(result: &ValueMap) -> anyhow::Result<&str> {
    result
        .get("generation")
        .and_then(Value::as_str)
        .context("result generation")
}

async fn stored(state: &Backend, owner: &str, id: &str) -> anyhow::Result<TaintedValue> {
    let observation = state
        .read_tainted(&memory_path(owner, DEFAULT_NAMESPACE, id)?)
        .await?;
    Ok(TaintedValue::new(
        observation.value.context("stored record")?,
        observation.taint,
    ))
}

#[tokio::test]
async fn operation_retries_reuse_committed_embedding_and_updates_compare_generation()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let calls = Arc::new(AtomicUsize::new(0));
    let driver =
        MemoryDriver::new(state.clone()).with_embedder(Arc::new(ChangingEmbedder(calls.clone())));
    let input = store_with_id(
        "owner",
        DEFAULT_NAMESPACE,
        "id",
        Value::string("first".into()),
    );
    let first = done_map(
        driver
            .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx(1))
            .await?,
    )?;
    let first_record = stored(&state, "owner", "id").await?;
    let repeated = done_map(
        driver
            .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx(1))
            .await?,
    )?;
    ensure!(
        Value::from(first.clone()) == Value::from(repeated) && calls.load(Ordering::Relaxed) == 1
    );
    ensure!(stored(&state, "owner", "id").await? == first_record);
    ensure!(failed(
        &driver
            .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx(2))
            .await
    ));
    ensure!(failed(
        &driver
            .call(
                MethodId::new(0),
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "id",
                    Value::string("different request".into())
                ),
                OutputMode::Unary,
                &ctx(1)
            )
            .await
    ));
    ensure!(
        calls.load(Ordering::Relaxed) == 1,
        "conflict called the embedder"
    );

    let mut replacement = update(
        store_with_id(
            "owner",
            DEFAULT_NAMESPACE,
            "id",
            Value::string("second".into()),
        ),
        result_generation(&first)?,
    )?
    .into_map()
    .context("replacement map")?;
    replacement.insert("tier".into(), Value::string("long_term".into()))?;
    let replacement = Value::from(replacement);
    let changed = done_map(
        driver
            .call(
                MethodId::new(3),
                replacement.clone(),
                OutputMode::Unary,
                &ctx(3),
            )
            .await?,
    )?;
    ensure!(
        result_generation(&changed)? != result_generation(&first)?
            && calls.load(Ordering::Relaxed) == 2
    );
    let current = stored(&state, "owner", "id").await?;
    ensure!(entry_required_str(&current.value, "tier")? == "long_term");
    ensure!(entry_required_field(&current.value, "content")? == &Value::string("second".into()));
    ensure!(
        Value::from(done_map(
            driver
                .call(
                    MethodId::new(3),
                    replacement.clone(),
                    OutputMode::Unary,
                    &ctx(3)
                )
                .await?
        )?) == Value::from(changed)
    );
    ensure!(failed(
        &driver
            .call(MethodId::new(3), replacement, OutputMode::Unary, &ctx(4))
            .await
    ));
    ensure!(calls.load(Ordering::Relaxed) == 2);
    ensure!(stored(&state, "owner", "id").await? == current);
    Ok(())
}

struct RacingEmbedder {
    gate: tokio::sync::Barrier,
    racing: AtomicBool,
}

struct ConcurrentChangingEmbedder {
    gate: tokio::sync::Barrier,
    calls: AtomicUsize,
}

#[async_trait]
impl InferenceBackend for ConcurrentChangingEmbedder {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::null())
    }
    async fn embed(&self, _input: &Value) -> Result<Value, String> {
        let value = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        let _arrival = self.gate.wait().await;
        Ok(Embedding {
            space_id: "concurrent-changing".into(),
            representation: EmbeddingRepresentation::Dense(
                vec![Value::integer(value as i64), Value::integer(1)].into(),
            ),
            embedding_model: None,
        }
        .into_value())
    }
}

#[tokio::test]
async fn concurrent_same_operation_retries_adopt_the_first_committed_representation()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let embedder = Arc::new(ConcurrentChangingEmbedder {
        gate: tokio::sync::Barrier::new(2),
        calls: AtomicUsize::new(0),
    });
    let driver = MemoryDriver::new(state.clone()).with_embedder(embedder.clone());
    let input = store_with_id(
        "owner",
        DEFAULT_NAMESPACE,
        "id",
        Value::string("same request".into()),
    );
    let context = ctx(1);
    let (left, right) = tokio::join!(
        driver.call(MethodId::new(0), input.clone(), OutputMode::Unary, &context),
        driver.call(MethodId::new(0), input.clone(), OutputMode::Unary, &context)
    );
    let (left, right) = (done_map(left?)?, done_map(right?)?);
    ensure!(result_generation(&left)? == result_generation(&right)?);
    let canonical = stored(&state, "owner", "id").await?;
    let retried = done_map(
        driver
            .call(MethodId::new(0), input, OutputMode::Unary, &context)
            .await?,
    )?;
    ensure!(result_generation(&retried)? == result_generation(&left)?);
    ensure!(embedder.calls.load(Ordering::Relaxed) == 2);
    ensure!(stored(&state, "owner", "id").await? == canonical);
    Ok(())
}

#[async_trait]
impl InferenceBackend for RacingEmbedder {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::null())
    }
    async fn embed(&self, input: &Value) -> Result<Value, String> {
        if self.racing.load(Ordering::Acquire) {
            let _arrival = self.gate.wait().await;
        }
        BagOfWordsEmbedder.embed(input).await
    }
}

#[tokio::test]
async fn concurrent_replacements_have_one_state_cas_winner_and_preserve_its_projection()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let embedder = Arc::new(RacingEmbedder {
        gate: tokio::sync::Barrier::new(2),
        racing: AtomicBool::new(false),
    });
    let driver = MemoryDriver::new(state.clone()).with_embedder(embedder.clone());
    let first = done_map(
        driver
            .call(
                MethodId::new(0),
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "id",
                    Value::string("coffee".into()),
                ),
                OutputMode::Unary,
                &ctx(1),
            )
            .await?,
    )?;
    let original = stored(&state, "owner", "id").await?;
    let generation = result_generation(&first)?;
    let left = update(
        store_with_id(
            "owner",
            DEFAULT_NAMESPACE,
            "id",
            Value::string("berlin".into()),
        ),
        generation,
    )?;
    let right = update(
        store_with_id(
            "owner",
            DEFAULT_NAMESPACE,
            "id",
            Value::string("morning".into()),
        ),
        generation,
    )?;
    embedder.racing.store(true, Ordering::Release);
    let left_ctx = ctx(2);
    let right_ctx = ctx(3);
    let (left, right) = tokio::join!(
        driver.call(MethodId::new(0), left, OutputMode::Unary, &left_ctx),
        driver.call(MethodId::new(0), right, OutputMode::Unary, &right_ctx)
    );
    ensure!(failed(&left) != failed(&right));
    let winner = if failed(&left) {
        done_map(right?)?
    } else {
        done_map(left?)?
    };
    let current = stored(&state, "owner", "id").await?;
    let indexed = indexed_entry(&current.value)?;
    ensure!(indexed.generation.as_str() == result_generation(&winner)?);
    ensure!(
        !driver.reindex_existing(&original).await?.0,
        "stale State read overwrote winner"
    );
    let input_taint = TaintSet::of(TaintSource::ModelOutput);
    let (removed, observed) = driver
        .delete_entry_with_index(&original, &input_taint)
        .await?;
    ensure!(!removed, "stale delete removed winner");
    ensure!(observed == input_taint.merged(&original.taint).merged(&current.taint));
    ensure!(stored(&state, "owner", "id").await? == current);
    let hits = done_list(
        driver
            .index
            .call(
                MethodId::new(1),
                Value::map(BTreeMap::from([
                    ("space_id".into(), Value::string(indexed.space_id)),
                    (
                        "representation".into(),
                        dense(Value::list(vec![Value::integer(1); 11])),
                    ),
                ])),
                OutputMode::Unary,
                &ctx(4),
            )
            .await?,
    )?;
    ensure!(
        hits.len() == 1
            && hits[0]
                .as_map()
                .and_then(|fields| fields.get("generation"))
                .and_then(Value::as_str)
                == Some(indexed.generation.as_str())
    );
    Ok(())
}

#[tokio::test]
async fn recall_repeats_after_stale_generation_and_missing_state_without_old_scores()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let local = driver(state.clone());
    let first = done_map(
        local
            .call(
                MethodId::new(0),
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "a",
                    Value::string("coffee".into()),
                ),
                OutputMode::Unary,
                &ctx(1),
            )
            .await?,
    )?;
    local
        .call(
            MethodId::new(0),
            store_with_id(
                "owner",
                DEFAULT_NAMESPACE,
                "b",
                Value::string("coffee morning".into()),
            ),
            OutputMode::Unary,
            &ctx(2),
        )
        .await?;
    let outside = driver(state.clone());
    let protected = TaintSet::of(TaintSource::Protected {
        path: memory_path("owner", DEFAULT_NAMESPACE, "a")?,
    });
    outside
        .call(
            MethodId::new(0),
            update(
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "a",
                    Value::string("berlin".into()),
                ),
                result_generation(&first)?,
            )?,
            OutputMode::Unary,
            &ctx(3).with_taint(protected),
        )
        .await?;
    let output = local
        .call(
            MethodId::new(1),
            recall_input("owner", DEFAULT_NAMESPACE, "coffee", 1),
            OutputMode::Unary,
            &ctx(4),
        )
        .await?;
    ensure!(output.taint.has_protected());
    let recalled = done_list(output)?;
    ensure!(
        recalled.len() == 1 && entry_required_str(&recalled[0], "id")? == "b",
        "new content was paired with old similarity"
    );
    state
        .write_delete(&memory_path("owner", DEFAULT_NAMESPACE, "b")?)
        .await?;
    state
        .write_delete(&memory_path("owner", DEFAULT_NAMESPACE, "a")?)
        .await?;
    ensure!(
        done_list(
            local
                .call(
                    MethodId::new(1),
                    recall_input("owner", DEFAULT_NAMESPACE, "coffee", 5),
                    OutputMode::Unary,
                    &ctx(5)
                )
                .await?
        )?
        .is_empty()
    );
    Ok(())
}

enum CommitAck {
    Pending,
    Error,
    SameValueConflict(TaintSet),
}

struct CommitWriter {
    base: Backend,
    ack: CommitAck,
    committed: AtomicBool,
}

impl StateWrite for CommitWriter {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let mutation = match (mutation, &self.ack) {
                (
                    StateMutation::CompareSet {
                        expected,
                        mut value,
                    },
                    CommitAck::SameValueConflict(extra),
                ) => {
                    value.taint.union(extra);
                    StateMutation::CompareSet { expected, value }
                }
                (mutation, _) => mutation,
            };
            self.base.mutate(path, mutation).await?;
            self.committed.store(true, Ordering::Release);
            match &self.ack {
                CommitAck::Pending => std::future::pending().await,
                CommitAck::Error => {
                    Err(StateError::Backend("commit acknowledgement unavailable".into()).into())
                }
                CommitAck::SameValueConflict(extra) => Err(StateFailure::new(
                    StateError::CasFailed {
                        path: path.to_string(),
                        expected: None,
                        actual: self.base.read(path).await?.map(Box::new),
                    },
                    extra.clone(),
                )),
            }
        })
    }
}

#[tokio::test]
async fn cancelled_or_uncertain_state_commits_are_rebuilt_without_network_embedding()
-> anyhow::Result<()> {
    for ack in [CommitAck::Pending, CommitAck::Error] {
        let base = InMemoryBackend::new().into_backend();
        let writer = Arc::new(CommitWriter {
            base: base.clone(),
            ack,
            committed: AtomicBool::new(false),
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let driver = MemoryDriver::new(base.clone().with_write(writer.clone()))
            .with_embedder(Arc::new(RemoteEmbedder(calls.clone())));
        let context = ctx(1);
        let mut request = Box::pin(driver.call(
            MethodId::new(0),
            store_with_id(
                "owner",
                DEFAULT_NAMESPACE,
                "id",
                Value::string("coffee".into()),
            ),
            OutputMode::Unary,
            &context,
        ));
        let result = request
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        ensure!(writer.committed.load(Ordering::Acquire));
        match &writer.ack {
            CommitAck::Pending => ensure!(result.is_pending()),
            CommitAck::Error => ensure!(result.is_ready()),
            CommitAck::SameValueConflict(_) => bail!("unexpected fixture"),
        }
        drop(request);
        let record = stored(&base, "owner", "id").await?;
        ensure!(record.taint.sources().contains(&TaintSource::ModelOutput));
        let restarted =
            MemoryDriver::new(base).with_embedder(Arc::new(RemoteEmbedder(calls.clone())));
        let rebuilt = restarted
            .call(
                MethodId::new(5),
                Value::map(BTreeMap::from([(
                    "owner".into(),
                    Value::string("owner".into()),
                )])),
                OutputMode::Unary,
                &ctx(2),
            )
            .await?;
        ensure!(rebuilt.outcome == Outcome::Done(Value::integer(1)));
        ensure!(
            calls.load(Ordering::Relaxed) == 1,
            "rebuild called remote embedding"
        );
        ensure!(
            done_list(
                restarted
                    .call(
                        MethodId::new(1),
                        recall_input("owner", DEFAULT_NAMESPACE, "coffee", 1),
                        OutputMode::Unary,
                        &ctx(3)
                    )
                    .await?
            )?
            .len()
                == 1
        );
    }
    Ok(())
}

#[tokio::test]
async fn equal_value_cas_conflict_uses_canonical_state_provenance_for_index_publication()
-> anyhow::Result<()> {
    let base = InMemoryBackend::new().into_backend();
    let protected = TaintSet::of(TaintSource::Protected {
        path: memory_path("owner", DEFAULT_NAMESPACE, "id")?,
    });
    let writer = Arc::new(CommitWriter {
        base: base.clone(),
        ack: CommitAck::SameValueConflict(protected),
        committed: AtomicBool::new(false),
    });
    let driver = driver(base.with_write(writer));
    let output = driver
        .call(
            MethodId::new(0),
            store_with_id(
                "owner",
                DEFAULT_NAMESPACE,
                "id",
                Value::string("coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    ensure!(matches!(output.outcome, Outcome::Done(_)) && output.taint.has_protected());
    let recall = driver
        .call(
            MethodId::new(1),
            recall_input("owner", DEFAULT_NAMESPACE, "coffee", 1),
            OutputMode::Unary,
            &ctx(2),
        )
        .await?;
    ensure!(recall.taint.has_protected());
    Ok(())
}

struct LatePages {
    page: StatePage,
}
impl StateQuery for LatePages {
    type Query<'a> = Ready<StateResult<StatePage>>;
    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        if query.cursor.is_some() {
            ready(Err(StateError::Backend("late page failed".into()).into()))
        } else {
            ready(Ok(self.page.clone()))
        }
    }
}

#[tokio::test]
async fn late_namespace_errors_keep_sources_already_seen_by_every_consumer() -> anyhow::Result<()> {
    for method in [1, 4, 5, 2] {
        let base = InMemoryBackend::new().into_backend();
        let creator = driver(base.clone());
        let path = memory_path("owner", DEFAULT_NAMESPACE, "id")?;
        creator
            .call(
                MethodId::new(0),
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "id",
                    Value::string("coffee".into()),
                ),
                OutputMode::Unary,
                &ctx(1).with_taint(TaintSet::of(TaintSource::Protected { path: path.clone() })),
            )
            .await?;
        let record = base.read_tainted(&path).await?;
        let record_value = record.value.clone().context("record")?;
        let page_taint = record
            .taint
            .clone()
            .merged(&TaintSet::of(TaintSource::ModelOutput));
        let query = Arc::new(LatePages {
            page: StatePage {
                taint: page_taint.clone(),
                entries: vec![(path.clone(), TaintedValue::new(record_value, record.taint))],
                next: Some(StateCursor(vec![1])),
                examined: 1,
                encoded_bytes: 1,
            },
        });
        let mut events = base.subscribe(&path).await?;
        let driver = driver(base.with_query(query));
        let operation_ctx = tainted_ctx(2);
        let output = driver
            .call(
                MethodId::new(method),
                Value::map(BTreeMap::from([
                    ("owner".into(), Value::string("owner".into())),
                    ("confirm_all".into(), Value::boolean(true)),
                    ("query".into(), Value::string("coffee".into())),
                    ("consistency".into(), Value::string("reconcile".into())),
                ])),
                OutputMode::Unary,
                &operation_ctx,
            )
            .await?;
        ensure!(output.taint.has_protected() && matches!(output.outcome, Outcome::Fail(_)));
        let expected = operation_ctx.taint.clone().merged(&page_taint);
        ensure!(output.taint.contains_all(&expected) && expected.contains_all(&output.taint));
        if method == 2 {
            ensure!(output.taint == expected);
            ensure!(
                events.try_recv()?
                    == xolotl_state::StateEvent::Delete {
                        path,
                        taint: expected
                    }
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn consolidation_retains_page_observations_in_empty_results_and_persisted_summaries()
-> anyhow::Result<()> {
    for include_entries in [false, true] {
        let base = InMemoryBackend::new().into_backend();
        let creator = driver(base.clone());
        let observed = TaintSet::of(TaintSource::Protected {
            path: memory_path("owner", DEFAULT_NAMESPACE, "observed_only")?,
        });
        let mut entries = Vec::new();
        if include_entries {
            for (operation, id, text) in [
                (1, "a", "coffee in the morning"),
                (2, "b", "morning coffee ritual"),
            ] {
                creator
                    .call(
                        MethodId::new(0),
                        store_with_id("owner", DEFAULT_NAMESPACE, id, Value::string(text.into())),
                        OutputMode::Unary,
                        &ctx(operation),
                    )
                    .await?;
                let path = memory_path("owner", DEFAULT_NAMESPACE, id)?;
                let entry = base.read_tainted(&path).await?;
                let entry_value = entry.value.clone().context("stored entry")?;
                ensure!(!entry.taint.has_protected());
                entries.push((path, TaintedValue::new(entry_value, entry.taint)));
            }
        }
        let query = Arc::new(LatePages {
            page: StatePage {
                taint: observed,
                examined: entries.len() + 1,
                entries,
                next: None,
                encoded_bytes: 0,
            },
        });
        let local = driver(base.with_query(query));
        let output = local
            .call(
                MethodId::new(4),
                Value::map(BTreeMap::from([(
                    "owner".into(),
                    Value::string("owner".into()),
                )])),
                OutputMode::Unary,
                &ctx(3),
            )
            .await?;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(i64::from(include_entries)))
                && output.taint.has_protected()
        );
        if include_entries {
            let (entries, _) = creator
                .load_namespace_entries("owner", DEFAULT_NAMESPACE)
                .await?;
            let (_, summary) = entries
                .iter()
                .find(|(_, entry)| entry_kind(&entry.value) == Some("summary"))
                .context("missing summary")?;
            ensure!(summary.taint.has_protected());
        }
    }
    Ok(())
}

#[tokio::test]
async fn protected_replacement_rejection_retains_canonical_record_sources() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let local = driver(state.clone());
    let protected = TaintSet::of(TaintSource::Protected {
        path: memory_path("owner", DEFAULT_NAMESPACE, "id")?,
    });
    let stored = done_map(
        local
            .call(
                MethodId::new(0),
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "id",
                    Value::string("coffee".into()),
                ),
                OutputMode::Unary,
                &ctx(1).with_taint(protected),
            )
            .await?,
    )?;
    let calls = Arc::new(AtomicUsize::new(0));
    let remote = MemoryDriver::new(state).with_embedder(Arc::new(RemoteEmbedder(calls.clone())));
    let output = remote
        .call(
            MethodId::new(0),
            update(
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "id",
                    Value::string("berlin".into()),
                ),
                result_generation(&stored)?,
            )?,
            OutputMode::Unary,
            &ctx(2),
        )
        .await?;
    ensure!(output.taint.has_protected() && matches!(output.outcome, Outcome::Fail(_)));
    ensure!(calls.load(Ordering::Relaxed) == 0);
    Ok(())
}

#[tokio::test]
async fn namespace_scan_preserves_records_before_an_oversized_provenance_header()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let creator = driver(state.clone());
    let prefix = namespace_path("owner", DEFAULT_NAMESPACE)?;
    let paths = ["a", "b", "c"]
        .map(|id| memory_path("owner", DEFAULT_NAMESPACE, id))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let large_taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse(&format!("state://private/{}", "s".repeat(1024 * 1024)))?,
    });
    for (index, id) in ["a", "b", "c"].into_iter().enumerate() {
        creator
            .call(
                MethodId::new(0),
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    id,
                    Value::string("coffee".into()),
                ),
                OutputMode::Unary,
                &ctx(index as u32 + 1).with_taint(if index == 1 {
                    large_taint.clone()
                } else {
                    TaintSet::of(TaintSource::ModelOutput)
                }),
            )
            .await?;
    }
    let mut scan = scan::NamespaceScan::new(&state, prefix);
    let mut actual = Vec::new();
    let mut observed = TaintSet::pristine();
    let mut pages = 0;
    while let Some(page) = scan.next().await? {
        pages += 1;
        ensure!(pages <= 4, "namespace scan did not terminate");
        observed.union(&page.taint);
        actual.extend(page.entries.into_iter().map(|(path, _)| path));
    }
    ensure!(actual == paths, "namespace scan lost records: {actual:?}");
    let expected = TaintSet::of(TaintSource::ModelOutput).merged(&large_taint);
    ensure!(observed == expected);
    let consumer = driver(state.clone());
    let loaded = consumer
        .load_namespace_entries("owner", DEFAULT_NAMESPACE)
        .await?;
    ensure!(loaded.0.iter().map(|(path, _)| path).eq(paths.iter()));
    ensure!(loaded.1 == expected);
    for (method, input) in [
        (
            5,
            Value::map(BTreeMap::from([(
                "owner".into(),
                Value::string("owner".into()),
            )])),
        ),
        (
            2,
            Value::map(BTreeMap::from([
                ("owner".into(), Value::string("owner".into())),
                ("confirm_all".into(), Value::boolean(true)),
            ])),
        ),
    ] {
        let output = consumer
            .call(MethodId::new(method), input, OutputMode::Unary, &ctx(9))
            .await?;
        ensure!(output.outcome == Outcome::Done(Value::integer(3)));
        ensure!(output.taint == expected);
    }
    for path in paths {
        ensure!(state.read_tainted(&path).await?.value.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn namespace_rebuild_reads_a_record_larger_than_its_page_window() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let creator = driver(state.clone());
    creator
        .call(
            MethodId::new(0),
            store_with_id(
                "owner",
                DEFAULT_NAMESPACE,
                "large",
                Value::string("coffee ".repeat(160_000)),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    ensure!(matches!(
        state
            .query(&StateScan::new(namespace_path("owner", DEFAULT_NAMESPACE)?))
            .await,
        Err(StateFailure {
            error: StateError::RowTooLarge(_),
            ..
        })
    ));
    let restarted = driver(state);
    let input = Value::map(BTreeMap::from([(
        "owner".into(),
        Value::string("owner".into()),
    )]));
    let rebuilt = restarted
        .call(MethodId::new(5), input.clone(), OutputMode::Unary, &ctx(2))
        .await?;
    ensure!(rebuilt.outcome == Outcome::Done(Value::integer(1)));
    ensure!(
        restarted
            .load_namespace_entries("owner", DEFAULT_NAMESPACE)
            .await?
            .0
            .len()
            == 1
    );
    let mut forget = input.into_map().context("forget input")?;
    forget.insert("confirm_all".into(), Value::boolean(true))?;
    ensure!(
        restarted
            .call(
                MethodId::new(2),
                Value::from(forget),
                OutputMode::Unary,
                &ctx(3)
            )
            .await?
            .outcome
            == Outcome::Done(Value::integer(1))
    );
    Ok(())
}

struct RelabelBeforeCas {
    base: Backend,
    extra: TaintSet,
}

impl StateWrite for RelabelBeforeCas {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if matches!(
                mutation,
                StateMutation::CompareSet {
                    expected: Some(_),
                    ..
                }
            ) {
                let mut current = self.base.read_tainted(path).await?;
                if let Some(value) = current.value {
                    current.taint.union(&self.extra);
                    self.base
                        .write_set_tainted(path, value, current.taint)
                        .await?;
                }
            }
            self.base.mutate(path, mutation).await
        })
    }
}

#[tokio::test]
async fn successful_cas_receipt_keeps_sources_added_after_the_memory_preread() -> anyhow::Result<()>
{
    let base = InMemoryBackend::new().into_backend();
    let protected = TaintSet::of(TaintSource::Protected {
        path: memory_path("owner", DEFAULT_NAMESPACE, "id")?,
    });
    let writer = Arc::new(RelabelBeforeCas {
        base: base.clone(),
        extra: protected,
    });
    let driver = driver(base.clone().with_write(writer));
    let first = done_map(
        driver
            .call(
                MethodId::new(0),
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "id",
                    Value::string("coffee".into()),
                ),
                OutputMode::Unary,
                &ctx(1),
            )
            .await?,
    )?;
    let changed = driver
        .call(
            MethodId::new(0),
            update(
                store_with_id(
                    "owner",
                    DEFAULT_NAMESPACE,
                    "id",
                    Value::string("berlin".into()),
                ),
                result_generation(&first)?,
            )?,
            OutputMode::Unary,
            &ctx(2),
        )
        .await?;
    ensure!(matches!(changed.outcome, Outcome::Done(_)) && changed.taint.has_protected());
    ensure!(stored(&base, "owner", "id").await?.taint.has_protected());
    let recalled = driver
        .call(
            MethodId::new(1),
            recall_input("owner", DEFAULT_NAMESPACE, "berlin", 1),
            OutputMode::Unary,
            &ctx(3),
        )
        .await?;
    ensure!(recalled.taint.has_protected() && done_list(recalled)?.len() == 1);
    Ok(())
}

struct VanishedOversizedRow {
    path: Path,
    taint: TaintSet,
}
impl StateQuery for VanishedOversizedRow {
    type Query<'a> = Ready<StateResult<StatePage>>;
    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        if query.cursor.is_some() {
            return ready(Ok(StatePage::empty()));
        }
        ready(Err(StateFailure::new(
            StateError::RowTooLarge(Box::new(xolotl_state::StateRowTooLarge {
                path: self.path.clone(),
                encoded_bytes: usize::MAX,
                provenance_observed: true,
                retry: None,
                resume: StateCursor(vec![1]),
            })),
            self.taint.clone(),
        )))
    }
}

#[tokio::test]
async fn oversized_scan_keeps_atomic_sources_when_the_following_point_read_is_absent()
-> anyhow::Result<()> {
    let path = memory_path("owner", DEFAULT_NAMESPACE, "vanished")?;
    let taint = TaintSet::of(TaintSource::Protected { path: path.clone() });
    let query = Arc::new(VanishedOversizedRow {
        path,
        taint: taint.clone(),
    });
    let driver = driver(InMemoryBackend::new().into_backend().with_query(query));
    let output = driver
        .call(
            MethodId::new(5),
            Value::map(BTreeMap::from([(
                "owner".into(),
                Value::string("owner".into()),
            )])),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    ensure!(output.outcome == Outcome::Done(Value::integer(0)) && output.taint == taint);
    Ok(())
}

struct ChangingMemoryRead {
    base: Backend,
    path: Path,
    reads: AtomicUsize,
    changes: AtomicUsize,
    every_read: bool,
}

impl StateRead for ChangingMemoryRead {
    type Read<'a> = Pin<Box<dyn Future<Output = StateResult<StateObservation>> + Send + 'a>>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            if path == &self.path {
                let read = self.reads.fetch_add(1, Ordering::Relaxed) + 1;
                if (self.every_read || read % 2 == 1)
                    && self
                        .changes
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                            remaining.checked_sub(1)
                        })
                        .is_ok()
                {
                    let current = self.base.read_tainted(path).await?;
                    let value = current
                        .value
                        .ok_or_else(|| StateError::NotFound(path.to_string()))?;
                    let mut entry = value
                        .into_map()
                        .ok_or_else(|| StateError::Serde("entry map".into()))?;
                    let mut metadata = entry
                        .get("index")
                        .cloned()
                        .and_then(Value::into_map)
                        .ok_or_else(|| StateError::Serde("index map".into()))?;
                    metadata.insert(
                        "generation".into(),
                        Value::string(format!("changed-{read}")),
                    )?;
                    entry.insert("index".into(), Value::from(metadata))?;
                    self.base
                        .write_set_tainted(
                            path,
                            Value::from(entry),
                            TaintSet::of(TaintSource::Fetched {
                                host: format!("change-{read}").into(),
                            }),
                        )
                        .await?;
                }
            }
            self.base.read_tainted(path).await
        })
    }
}

async fn competing_memory(
    method: u64,
    attempts: usize,
    changes: usize,
) -> anyhow::Result<(MemoryDriver, Arc<ChangingMemoryRead>, Value)> {
    let base = InMemoryBackend::new().into_backend();
    let index = Arc::new(IndexDriver::new());
    let creator =
        driver(base.clone()).with_retrieval_stack(index.clone(), Arc::new(RankerDriver::new()));
    creator
        .call(
            MethodId::new(0),
            store_with_id(
                "owner",
                DEFAULT_NAMESPACE,
                "id",
                Value::string("coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    let reader = Arc::new(ChangingMemoryRead {
        base: base.clone(),
        path: memory_path("owner", DEFAULT_NAMESPACE, "id")?,
        reads: AtomicUsize::new(0),
        changes: AtomicUsize::new(changes),
        every_read: method == 5,
    });
    let memory = driver(base.with_read(reader.clone()))
        .with_retrieval_stack(index, Arc::new(RankerDriver::new()))
        .with_repair_attempts(std::num::NonZeroUsize::new(attempts).context("zero attempts")?);
    let input = if method == 1 {
        recall_input("owner", DEFAULT_NAMESPACE, "coffee", 1)
    } else {
        Value::map(BTreeMap::from([(
            "owner".into(),
            Value::string("owner".into()),
        )]))
    };
    Ok((memory, reader, input))
}

#[tokio::test]
async fn competing_recall_and_rebuild_exhaust_attempts_with_all_observed_sources()
-> anyhow::Result<()> {
    for method in [1, 5] {
        for attempts in [1, 3] {
            let (memory, reader, input) = competing_memory(method, attempts, usize::MAX).await?;
            let context = tainted_ctx(2);
            let mut request =
                Box::pin(memory.call(MethodId::new(method), input, OutputMode::Unary, &context));
            let mut completed = None;
            for _ in 0..16 {
                if let std::task::Poll::Ready(output) = request
                    .as_mut()
                    .poll(&mut TaskContext::from_waker(Waker::noop()))
                {
                    completed = Some(output);
                    break;
                }
            }
            let output =
                completed.context("repair did not terminate within its attempt budget")??;
            ensure!(
                matches!(output.outcome, Outcome::Fail(Failure::HandlerError { ref kind, .. }) if kind == "memory_repair_exhausted")
            );
            ensure!(reader.reads.load(Ordering::Relaxed) == 2 * attempts);
            let mut expected = context.taint.clone();
            expected.add(TaintSource::ModelOutput);
            for read in 1..=2 * attempts {
                if method == 5 || read % 2 == 1 {
                    expected.add(TaintSource::Fetched {
                        host: format!("change-{read}").into(),
                    });
                }
            }
            ensure!(
                output.taint.contains_all(&expected) && expected.contains_all(&output.taint),
                "method={method} attempts={attempts} observed={:?} expected={expected:?}",
                output.taint
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn finite_memory_competition_succeeds_and_cancellation_stops_repair() -> anyhow::Result<()> {
    for method in [1, 5] {
        let (memory, reader, input) = competing_memory(method, 3, 2).await?;
        let output = memory
            .call(MethodId::new(method), input, OutputMode::Unary, &ctx(2))
            .await?;
        if method == 1 {
            let recalled = done_list(output)?;
            ensure!(recalled.len() == 1);
            let current = reader
                .base
                .read_tainted(&reader.path)
                .await?
                .value
                .context("missing current memory")?;
            ensure!(
                indexed_entry(&recalled[0])?.generation.as_str()
                    == indexed_entry(&current)?.generation.as_str()
            );
            ensure!(reader.reads.load(Ordering::Relaxed) == 5);
        } else {
            ensure!(output.outcome == Outcome::Done(Value::integer(1)));
            ensure!(reader.reads.load(Ordering::Relaxed) == 3);
        }
        let (memory, reader, input) = competing_memory(method, 3, usize::MAX).await?;
        let context = ctx(3);
        let mut request =
            Box::pin(memory.call(MethodId::new(method), input, OutputMode::Unary, &context));
        ensure!(
            request
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop()))
                .is_pending()
        );
        let reads = reader.reads.load(Ordering::Relaxed);
        ensure!(reads == 2);
        drop(request);
        tokio::task::yield_now().await;
        ensure!(reader.reads.load(Ordering::Relaxed) == reads);
    }
    Ok(())
}

struct UnavailableRankWeights {
    base: Backend,
    taint: TaintSet,
}

impl StateRead for UnavailableRankWeights {
    type Read<'a> = Pin<Box<dyn Future<Output = StateResult<StateObservation>> + Send + 'a>>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            if path.to_string() == "state://kernel/rank/weights" {
                return Err(StateFailure::new(
                    StateError::Backend("rank weights unavailable".into()),
                    self.taint.clone(),
                ));
            }
            self.base.read_tainted(path).await
        })
    }
}

#[tokio::test]
async fn memory_recall_preserves_the_rankers_failure_class_and_sources() -> anyhow::Result<()> {
    let base = InMemoryBackend::new().into_backend();
    let sources = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://rank-policy")?,
    });
    let state = base.clone().with_read(Arc::new(UnavailableRankWeights {
        base,
        taint: sources.clone(),
    }));
    let memory = driver(state.clone()).with_retrieval_stack(
        Arc::new(IndexDriver::new()),
        Arc::new(RankerDriver::new().with_state(state)),
    );
    memory
        .call(
            MethodId::new(0),
            store_with_id(
                "owner",
                DEFAULT_NAMESPACE,
                "id",
                Value::string("coffee".into()),
            ),
            OutputMode::Unary,
            &ctx(1),
        )
        .await?;
    let output = memory
        .call(
            MethodId::new(1),
            recall_input("owner", DEFAULT_NAMESPACE, "coffee", 1),
            OutputMode::Unary,
            &tainted_ctx(2),
        )
        .await?;
    ensure!(
        matches!(output.outcome, Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "rank")
    );
    ensure!(
        output.taint.contains_all(&sources) && output.taint.contains_all(&tainted_ctx(2).taint)
    );
    Ok(())
}
