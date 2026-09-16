//! Real Standard Memory/Index and a portable retrieval-to-generation program.
//! Only embedding and token generation are deterministic local test adapters;
//! permission admission, indexing, source propagation and streaming are real.

use super::support::{Running, invoke, record, request, stream};
use anyhow::{Context, bail, ensure};
use async_trait::async_trait;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::Poll;
use std::time::Duration;
use xolotl_kernel::{DriverOutput, host::stream::StreamItem};
use xolotl_sdk::{
    ExecutionOutput, Expression, Failure, InferenceBackend, ModelCapabilities, OperationTemplate,
    Outcome, Path, PreparedProgram, Program, RequestProcess, ResourceName, StandardConfig,
    StandardModule, StandardModules, TaintSet, TaintedValue, Transform, Value, Xolotl,
    XolotlBuilder,
};
use xolotl_standard::{Embedding, EmbeddingRepresentation, InferenceStream, RetrievalConfig};
use xolotl_state::{Backend, InMemoryBackend, StatePage, StateQuery, StateResult, StateScan};
use xolotl_types::{OutputMode, TaintSource};

const STORE: &str = "perform://effect/memory/store";
const RECALL: &str = "perform://effect/memory/recall";
const INFER: &str = "perform://effect/inference/infer";
const QUESTION: &str = "coffee morning routine";
const COFFEE: &str = "coffee morning checklist warm the cup grind beans and brew";
const DOCUMENTS: [(&str, &str); 2] = [
    ("coffee", COFFEE),
    ("travel", "travel train berlin timetable"),
];

/// Keep the real backend's cursor, rows and sources; only narrow its page window.
struct SingleRowPages {
    state: Backend,
    pages: AtomicUsize,
    continuations: AtomicUsize,
    rows: AtomicUsize,
    max_rows: AtomicUsize,
}

impl StateQuery for SingleRowPages {
    type Query<'a> = Pin<Box<dyn Future<Output = StateResult<StatePage>> + Send + 'a>>;

    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        Box::pin(async move {
            let mut query = query.clone();
            query.limits.entries = NonZeroUsize::MIN;
            let page = self.state.query(&query).await?;
            self.pages.fetch_add(1, Ordering::SeqCst);
            self.continuations
                .fetch_add(usize::from(query.cursor.is_some()), Ordering::SeqCst);
            self.rows.fetch_add(page.entries.len(), Ordering::SeqCst);
            self.max_rows
                .fetch_max(page.entries.len(), Ordering::SeqCst);
            Ok(page)
        })
    }
}

#[derive(Default)]
struct LocalModel {
    embeddings: AtomicUsize,
    streams: AtomicUsize,
    active: AtomicUsize,
    released: AtomicUsize,
    attempted: AtomicUsize,
    emitted: AtomicUsize,
}

struct ModelSession<'a>(&'a LocalModel);

impl Drop for ModelSession<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.released.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl InferenceBackend for LocalModel {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Err("this scenario requires the streaming generation path".into())
    }

    async fn embed(&self, input: &Value) -> Result<Value, String> {
        let text = input.as_str().ok_or("expected Memory's text projection")?;
        self.embeddings.fetch_add(1, Ordering::SeqCst);
        let vector = [
            Value::integer(1),
            Value::integer(i64::from(
                text.split_whitespace().any(|word| word == "coffee"),
            )),
            Value::integer(i64::from(
                text.split_whitespace().any(|word| word == "travel"),
            )),
        ];
        Ok(Embedding {
            space_id: "scenario-bow".into(),
            representation: EmbeddingRepresentation::Dense(vector.into_iter().collect()),
            embedding_model: Some("local/deterministic".into()),
        }
        .into_value())
    }

    async fn infer_stream(
        &self,
        input: &Value,
        stream: &InferenceStream<'_>,
    ) -> Result<DriverOutput, String> {
        let pair = input
            .as_list()
            .filter(|pair| pair.len() == 2)
            .ok_or("prepared program did not pair question and recall")?;
        if pair.get(0).and_then(Value::as_str) != Some(QUESTION) {
            return Err("the original question did not reach generation".into());
        }
        let records = pair
            .get(1)
            .and_then(Value::as_list)
            .filter(|records| records.len() == 1)
            .ok_or("Memory did not select exactly one record")?;
        let entry = records
            .get(0)
            .and_then(Value::as_map)
            .ok_or("missing recalled record")?;
        if entry.get("id").and_then(Value::as_str) != Some("coffee") {
            return Err("real index ranking selected the unrelated record".into());
        }
        let content = entry
            .get("content")
            .and_then(Value::as_str)
            .ok_or("missing record content")?;
        if content != COFFEE
            || entry
                .get("index")
                .and_then(Value::as_map)
                .and_then(|index| index.get("generation"))
                .and_then(Value::as_str)
                .is_none()
        {
            return Err("generation did not receive the stored record and its generation".into());
        }
        self.streams.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        let _session = ModelSession(self);
        // Project the actual selected record incrementally. No whole generated
        // answer or detached producer is retained by this local model fixture.
        for (index, word) in content.split_whitespace().enumerate() {
            let token = if index == 0 {
                word.into()
            } else {
                format!(" {word}")
            };
            self.attempted.fetch_add(1, Ordering::SeqCst);
            stream.emit(Value::string(token)).await?;
            self.emitted.fetch_add(1, Ordering::SeqCst);
        }
        Ok(DriverOutput::new(Outcome::Done(Value::null())))
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            streaming: true,
            ..ModelCapabilities::default()
        }
    }
}

struct Fixture {
    runtime: Xolotl,
    model: Arc<LocalModel>,
    store: PreparedProgram,
    rag: PreparedProgram,
    handles: usize,
    processes: usize,
    pages: Arc<SingleRowPages>,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let model = Arc::new(LocalModel::default());
        let state = InMemoryBackend::new().into_backend();
        let pages = Arc::new(SingleRowPages {
            state: state.clone(),
            pages: AtomicUsize::new(0),
            continuations: AtomicUsize::new(0),
            rows: AtomicUsize::new(0),
            max_rows: AtomicUsize::new(0),
        });
        let config = StandardConfig::default()
            .with_modules(
                StandardModules::none()
                    .with(StandardModule::Memory)
                    .with(StandardModule::Index)
                    .with(StandardModule::Inference),
            )
            .with_retrieval(RetrievalConfig::default().with_work_quantum(NonZeroUsize::MIN))
            .with_inference_backend(model.clone());
        let runtime = XolotlBuilder::new()
            .with_state_backend(state.with_query(pages.clone()))
            .with_process_capacity(NonZeroUsize::MIN.saturating_add(1))
            .build_with_standard(&config)?;
        let handles = runtime.bootstrap().kernel.handles.read().len();
        let processes = runtime.bootstrap().kernel.processes.len();
        let store = invoke(
            ResourceName::new(Path::parse("effect://memory/store")?),
            OutputMode::Unary,
        )?;
        // Both branches receive the admitted query. Recall's sources join the
        // question before the next real inference invocation sees the pair.
        let rag = PreparedProgram::new(
            &Program::new(
                Expression::Parallel {
                    left: Box::new(Expression::Transform {
                        operation: Transform::Field {
                            name: "query".into(),
                        },
                    }),
                    right: Box::new(operation("effect://memory/recall", OutputMode::Unary)?),
                }
                .then(operation("effect://inference/infer", OutputMode::Stream)?),
            )
            .compile()?,
        )?;
        Ok(Self {
            runtime,
            model,
            store,
            rag,
            handles,
            processes,
            pages,
        })
    }

    async fn finish(
        &self,
        request: RequestProcess<'_>,
        output: &ExecutionOutput,
    ) -> anyhow::Result<()> {
        let process = request.id();
        request.finish(output).await?;
        let kernel = &self.runtime.bootstrap().kernel;
        ensure!(
            kernel
                .processes
                .status(process)
                .is_some_and(|status| status.is_terminal())
        );
        ensure!(
            kernel.handles.read().len() == self.handles,
            "request retained capability handles"
        );
        ensure!(kernel.processes.reap_finalized(1) == 1);
        ensure!(
            kernel.processes.len() == self.processes,
            "completed request still occupies admission"
        );
        Ok(())
    }

    async fn seed(&self) -> anyhow::Result<()> {
        for (id, text) in DOCUMENTS {
            let request = request(self.runtime.bootstrap(), &[STORE])?;
            let output = request
                .executor()
                .eval_prepared(&self.store, document(id, text)?)
                .await;
            let Outcome::Done(receipt) = &output.outcome else {
                bail!("Memory store failed: {output:?}");
            };
            let receipt = receipt.as_map().context("missing store receipt")?;
            ensure!(receipt.get("indexed").and_then(Value::as_bool) == Some(true));
            let path = receipt
                .get("path")
                .and_then(Value::as_str)
                .context("missing stored path")?;
            let saved = self
                .runtime
                .bootstrap()
                .kernel
                .state
                .read_tainted(&Path::parse(path)?)
                .await?
                .context("Memory did not persist its record")?;
            let saved_fields = saved
                .value
                .as_map()
                .context("invalid stored memory record")?;
            ensure!(saved_fields.get("content").and_then(Value::as_str) == Some(text));
            let index = saved_fields
                .get("index")
                .and_then(Value::as_map)
                .context("missing stored index representation")?;
            ensure!(index.get("generation") == receipt.get("generation"));
            ensure!(saved.taint.contains_all(&source(id)?));
            ensure!(saved.taint.sources().contains(&TaintSource::ModelOutput));
            ensure!(output.taint.contains_all(&saved.taint));
            self.finish(request, &output).await?;
        }
        ensure!(self.model.embeddings.load(Ordering::SeqCst) == DOCUMENTS.len());
        Ok(())
    }

    async fn recall_across_pages(&self) -> anyhow::Result<()> {
        let recall = invoke(
            ResourceName::new(Path::parse("effect://memory/recall")?),
            OutputMode::Unary,
        )?;
        let request = request(self.runtime.bootstrap(), &[RECALL])?;
        let mut input = question();
        let mut fields = input.value.into_map().context("question fields")?;
        fields.insert("k".into(), Value::integer(DOCUMENTS.len() as i64))?;
        input.value = Value::from(fields);
        let before = (
            self.pages.pages.load(Ordering::SeqCst),
            self.pages.continuations.load(Ordering::SeqCst),
            self.pages.rows.load(Ordering::SeqCst),
        );
        let output = request.executor().eval_prepared(&recall, input).await;
        let Outcome::Done(value) = &output.outcome else {
            bail!("paged recall failed: {output:?}");
        };
        let records = value.as_list().context("recall records")?;
        ensure!(records.len() == DOCUMENTS.len());
        for ((id, text), record) in DOCUMENTS.iter().zip(records.iter()) {
            let record = record.as_map().context("recalled record")?;
            ensure!(record.get("id").and_then(Value::as_str) == Some(*id));
            ensure!(record.get("content").and_then(Value::as_str) == Some(*text));
        }
        ensure!(output.taint.contains_all(&observed_sources()?));
        ensure!(self.pages.pages.load(Ordering::SeqCst) - before.0 >= DOCUMENTS.len());
        ensure!(self.pages.continuations.load(Ordering::SeqCst) > before.1);
        ensure!(self.pages.rows.load(Ordering::SeqCst) - before.2 == DOCUMENTS.len());
        ensure!(self.pages.max_rows.load(Ordering::SeqCst) == 1);
        self.finish(request, &output).await
    }
}

fn operation(target: &str, output: OutputMode) -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse(target)?),
            method: "invoke".into(),
            method_id: None,
            output,
            literal_input: None,
        },
    })
}

fn source(id: &str) -> anyhow::Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected {
        path: Path::parse(&format!("state://notes/{id}"))?,
    }))
}

fn document(id: &str, text: &str) -> anyhow::Result<TaintedValue> {
    Ok(TaintedValue::new(
        record([
            ("owner", Value::string("rag".into())),
            ("namespace", Value::string("notes".into())),
            ("id", Value::string(id.into())),
            ("content", Value::string(text.into())),
        ]),
        source(id)?,
    ))
}

fn question() -> TaintedValue {
    TaintedValue::new(
        record([
            ("owner", Value::string("rag".into())),
            ("namespace", Value::string("notes".into())),
            ("query", Value::string(QUESTION.into())),
            ("k", Value::integer(1)),
            ("consistency", Value::string("reconcile".into())),
        ]),
        TaintSet::of(TaintSource::Inbound {
            source: "rag-user".into(),
            channel: "question".into(),
        }),
    )
}

fn observed_sources() -> anyhow::Result<TaintSet> {
    let mut sources = question().taint;
    // Both candidates affect ranking, including the one that is not returned.
    for (id, _) in DOCUMENTS {
        sources.union(&source(id)?);
    }
    sources.add(TaintSource::ModelOutput);
    Ok(sources)
}

fn denied_at_open(output: &ExecutionOutput) -> anyhow::Result<()> {
    ensure!(
        matches!(&output.outcome,
        Outcome::Fail(Failure::PolicyViolation { policy, .. }) if policy == "open"),
        "missing request grant was not rejected during capability admission: {output:?}"
    );
    Ok(())
}

#[tokio::test]
async fn prepared_rag_uses_real_retrieval_authority_and_stream_backpressure() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = Fixture::new()?;
        let denied = request(fixture.runtime.bootstrap(), &[])?;
        let output = denied
            .executor()
            .eval_prepared(&fixture.store, document("coffee", COFFEE)?)
            .await;
        denied_at_open(&output)?;
        ensure!(output.taint.contains_all(&source("coffee")?));
        ensure!(fixture.model.embeddings.load(Ordering::SeqCst) == 0);
        ensure!(
            fixture
                .runtime
                .bootstrap()
                .kernel
                .state
                .read(&Path::parse("state://memory/rag/notes/coffee")?)
                .await?
                .is_none()
        );
        fixture.finish(denied, &output).await?;
        fixture.seed().await?;
        fixture.recall_across_pages().await?;
        let observed = observed_sources()?;
        for capabilities in [&[INFER][..], &[RECALL][..]] {
            let denied = request(fixture.runtime.bootstrap(), capabilities)?;
            let output = denied
                .executor()
                .eval_prepared(&fixture.rag, question())
                .await;
            denied_at_open(&output)?;
            ensure!(fixture.model.streams.load(Ordering::SeqCst) == 0);
            if capabilities == [RECALL] {
                ensure!(output.taint.contains_all(&observed));
            }
            fixture.finish(denied, &output).await?;
        }
        for run in 0..2 {
            let request = request(fixture.runtime.bootstrap(), &[RECALL, INFER])?;
            let (route, mut receiver) = stream();
            let executor = request.executor().with_stream_router(route);
            let attempted = fixture.model.attempted.load(Ordering::SeqCst);
            let emitted = fixture.model.emitted.load(Ordering::SeqCst);
            let mut running = Running::new(executor.eval_prepared(&fixture.rag, question()));
            let mut answer = String::new();
            loop {
                match running.next(&mut receiver).await? {
                    StreamItem::Chunk(chunk) => {
                        ensure!(chunk.taint.contains_all(&observed));
                        if answer.is_empty() {
                            running.pending().await?;
                            ensure!(fixture.model.active.load(Ordering::SeqCst) == 1);
                            ensure!(
                                fixture.model.attempted.load(Ordering::SeqCst) == attempted + 2
                            );
                            ensure!(
                                fixture.model.emitted.load(Ordering::SeqCst) == emitted + 1,
                                "borrowed token lost stream credit"
                            );
                        }
                        answer.push_str(chunk.value.as_str().context("non-text generation chunk")?);
                        drop(chunk);
                    }
                    StreamItem::End(end) => {
                        ensure!(end.outcome.is_ok() && end.taint.contains_all(&observed));
                        break;
                    }
                }
            }
            ensure!(answer == COFFEE);
            let output = running.finish().await;
            ensure!(output.outcome == Outcome::Done(Value::null()));
            ensure!(output.taint.contains_all(&observed));
            ensure!(receiver.recv().await.is_none());
            ensure!(fixture.model.active.load(Ordering::SeqCst) == 0);
            ensure!(fixture.model.released.load(Ordering::SeqCst) == run + 1);
            fixture.finish(request, &output).await?;
        }
        anyhow::Ok(())
    })
    .await
    .context("RAG composition timed out")?
}

#[tokio::test]
async fn cancelling_rag_generation_releases_model_ownership_before_borrowed_output()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = Fixture::new()?;
        fixture.seed().await?;
        let request = request(fixture.runtime.bootstrap(), &[RECALL, INFER])?;
        let (route, mut receiver) = stream();
        let executor = request.executor().with_stream_router(route);
        let mut running = Running::new(executor.eval_prepared(&fixture.rag, question()));
        let StreamItem::Chunk(chunk) = running.next(&mut receiver).await? else {
            bail!("RAG generation ended before its first token");
        };
        let observed = observed_sources()?;
        ensure!(chunk.taint.contains_all(&observed));
        ensure!(fixture.model.active.load(Ordering::SeqCst) == 1);
        drop(running);
        ensure!(fixture.model.active.load(Ordering::SeqCst) == 0);
        ensure!(fixture.model.released.load(Ordering::SeqCst) == 1);
        ensure!(
            poll_fn(|cx| Poll::Ready(receiver.poll_recv(cx).is_pending())).await,
            "terminal passed output whose credit is still borrowed"
        );
        drop(chunk);
        let Some(StreamItem::End(end)) = receiver.recv().await else {
            bail!("cancelled RAG stream lost its terminal");
        };
        ensure!(end.outcome == Err(Failure::Cancelled));
        ensure!(end.taint.contains_all(&observed));
        fixture
            .finish(
                request,
                &ExecutionOutput::new(Outcome::Fail(Failure::Cancelled), end.taint),
            )
            .await?;
        anyhow::Ok(())
    })
    .await
    .context("RAG cancellation timed out")?
}
