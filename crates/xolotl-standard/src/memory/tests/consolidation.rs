use super::*;
use crate::memory::consolidation::{ConsolidationLimits, TokenWork, word_overlap};
use parking_lot::Mutex;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll, Waker};
use xolotl_state::{
    StateBoundedRead, StateCommit, StateMutation, StateObservation, StatePage, StateQuery,
    StateRead, StateResult, StateScan, StateWrite,
};

fn limits(
    records: usize,
    encoded_bytes: usize,
    text_bytes: usize,
) -> anyhow::Result<ConsolidationLimits> {
    Ok(ConsolidationLimits {
        records: NonZeroUsize::new(records).context("positive test record limit")?,
        encoded_bytes: NonZeroUsize::new(encoded_bytes).context("positive test encoded limit")?,
        text_bytes: NonZeroUsize::new(text_bytes).context("positive test text limit")?,
    })
}

async fn seed_entries(state: &Backend) -> anyhow::Result<()> {
    let memory = driver(state.clone());
    for (position, id) in ["a", "b", "c"].into_iter().enumerate() {
        let path = memory_path("owner", DEFAULT_NAMESPACE, id)?;
        let input = BTreeMap::from([("content".into(), Value::string("coffee morning".into()))]);
        let entry = build_entry(
            "owner",
            DEFAULT_NAMESPACE,
            id,
            if id == "c" {
                Tier::Archive
            } else {
                Tier::Working
            },
            &input.into(),
            &ctx(position as u32),
        )?;
        let mut entry = TaintedValue::new(
            entry,
            TaintSet::of(TaintSource::Protected { path: path.clone() }),
        );
        memory
            .write_indexed_entry(&path, &mut entry, None, None, &ctx(position as u32))
            .await?;
    }
    Ok(())
}

struct BoundedScanProbe {
    base: Backend,
    reads: AtomicUsize,
    bounded_limits: Mutex<Vec<usize>>,
    page_limits: Mutex<Vec<(usize, usize)>>,
    writes: AtomicUsize,
}

impl StateRead for BoundedScanProbe {
    type Read<'a> = Ready<StateResult<StateObservation>>;

    fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        ready(Err(StateError::Backend(
            "unexpected unrestricted consolidation read".into(),
        )
        .into()))
    }
}

impl StateBoundedRead for BoundedScanProbe {
    type BoundedRead<'a> = Pin<Box<dyn Future<Output = StateResult<StateObservation>> + Send + 'a>>;

    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        limit: NonZeroUsize,
    ) -> Self::BoundedRead<'a> {
        self.bounded_limits.lock().push(limit.get());
        Box::pin(self.base.read_tainted_bounded(path, limit))
    }
}

impl StateQuery for BoundedScanProbe {
    type Query<'a> = Pin<Box<dyn Future<Output = StateResult<StatePage>> + Send + 'a>>;

    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        self.page_limits
            .lock()
            .push((query.limits.entries.get(), query.limits.encoded_bytes.get()));
        Box::pin(self.base.query(query))
    }
}

impl StateWrite for BoundedScanProbe {
    type Write<'a> = Ready<StateResult<StateCommit>>;

    fn mutate<'a>(&'a self, _path: &'a Path, _mutation: StateMutation) -> Self::Write<'a> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        ready(Err(StateError::Backend(
            "unexpected consolidation write".into(),
        )
        .into()))
    }
}

#[tokio::test]
async fn oversized_consolidation_rows_use_only_bounded_reads_and_never_write() -> anyhow::Result<()>
{
    let state = InMemoryBackend::new().into_backend();
    seed_entries(&state).await?;
    let path = memory_path("owner", DEFAULT_NAMESPACE, "c")?;
    let original = state.read_tainted(&path).await?;
    let mut large = original
        .value
        .context("missing seeded record")?
        .into_map()
        .context("record map")?;
    large.insert("content".into(), Value::string("x".repeat(1024 * 1024)))?;
    state
        .write_set_tainted(&path, Value::from(large), original.taint)
        .await?;
    let probe = Arc::new(BoundedScanProbe {
        base: state.clone(),
        reads: AtomicUsize::new(0),
        bounded_limits: Mutex::new(Vec::new()),
        page_limits: Mutex::new(Vec::new()),
        writes: AtomicUsize::new(0),
    });
    let instrumented = state
        .clone()
        .with_read(probe.clone())
        .with_bounded_read(probe.clone())
        .with_query(probe.clone())
        .with_write(probe.clone());
    let memory = driver(instrumented).with_consolidation_limits(limits(8, 4096, 4096)?);
    let context = tainted_ctx(20);
    let error = memory
        .consolidate_from_input(
            &BTreeMap::from([("owner".into(), Value::string("owner".into()))]).into(),
            &context,
        )
        .await
        .err()
        .context("oversized row was admitted")?;
    ensure!(error.to_string().contains("encoded byte budget"));
    ensure!(error.taint.has_protected() && error.taint.contains_all(&context.taint));
    ensure!(probe.reads.load(Ordering::Relaxed) == 0);
    ensure!(probe.writes.load(Ordering::Relaxed) == 0);
    ensure!(probe.bounded_limits.lock().as_slice() == [4096]);
    let pages = probe.page_limits.lock().clone();
    ensure!(pages.len() >= 2 && pages[0] == (8, 4096));
    ensure!(pages[1].0 < pages[0].0 && pages[1].1 < pages[0].1);
    let (stored, _) = driver(state.clone())
        .load_namespace_entries("owner", DEFAULT_NAMESPACE)
        .await?;
    ensure!(
        stored.len() == 3
            && stored
                .iter()
                .all(|(_, entry)| entry_kind(&entry.value) != Some("summary"))
    );
    let (admitted, _) = memory
        .load_namespace_entries_with_limits(
            "owner",
            DEFAULT_NAMESPACE,
            Some(limits(8, 2 * 1024 * 1024, 2 * 1024 * 1024)?),
        )
        .await?;
    ensure!(admitted == stored);
    ensure!(probe.bounded_limits.lock().as_slice() == [4096, 2 * 1024 * 1024]);
    let missing_port = driver(
        Backend::default()
            .with_read(probe.clone())
            .with_query(probe.clone())
            .with_write(probe.clone()),
    )
    .with_consolidation_limits(limits(8, 4096, 4096)?);
    let error = missing_port
        .load_namespace_entries_with_limits(
            "owner",
            DEFAULT_NAMESPACE,
            Some(limits(8, 4096, 4096)?),
        )
        .await
        .err()
        .context("missing bounded-read capability was bypassed")?;
    ensure!(error.to_string().contains("bounded_read"));
    ensure!(probe.reads.load(Ordering::Relaxed) == 0 && probe.writes.load(Ordering::Relaxed) == 0);
    Ok(())
}

#[tokio::test]
async fn admission_is_inclusive_and_rejection_never_writes_summaries() -> anyhow::Result<()> {
    for rejected_limit in 0..4 {
        let state = InMemoryBackend::new().into_backend();
        seed_entries(&state).await?;
        let memory = driver(state);
        let (before, _) = memory
            .load_namespace_entries("owner", DEFAULT_NAMESPACE)
            .await?;
        let encoded_bytes = before.iter().try_fold(0, |total, (_, entry)| {
            xolotl_state::host::encoded_size(entry).map(|bytes| total + bytes)
        })?;
        let text_bytes: usize = before
            .iter()
            .map(|(_, entry)| entry_text(&entry.value).len())
            .sum();
        let admitted = limits(
            before.len() - usize::from(rejected_limit == 1),
            encoded_bytes - usize::from(rejected_limit == 2),
            text_bytes - usize::from(rejected_limit == 3),
        )?;
        let memory = memory.with_consolidation_limits(admitted);
        let context = tainted_ctx(10);
        let result = memory
            .consolidate_from_input(
                &BTreeMap::from([("owner".into(), Value::string("owner".into()))]).into(),
                &context,
            )
            .await;
        let (after, _) = memory
            .load_namespace_entries("owner", DEFAULT_NAMESPACE)
            .await?;
        if rejected_limit == 0 {
            let output = result?;
            ensure!(output.outcome == Outcome::Done(Value::integer(1)));
            ensure!(output.taint.has_protected());
            ensure!(after.len() == before.len() + 1);
        } else {
            let error = result.err().context("over-budget namespace was admitted")?;
            ensure!(error.to_string().contains(match rejected_limit {
                1 => "record limit",
                2 => "encoded byte limit",
                _ => "text byte limit",
            }));
            ensure!(error.taint.has_protected());
            ensure!(error.taint.contains_all(&context.taint));
            ensure!(after == before, "admission failure mutated stored memory");
        }
    }
    Ok(())
}

#[tokio::test]
async fn consolidation_keeps_asymmetric_seed_clustering() -> anyhow::Result<()> {
    let mut entries = Vec::new();
    for (position, content) in ["a b", "a b c d e f", "e f"].into_iter().enumerate() {
        let id = format!("entry-{position}");
        let entry = build_entry(
            "owner",
            DEFAULT_NAMESPACE,
            &id,
            Tier::Working,
            &BTreeMap::from([("content".into(), Value::string(content.into()))]).into(),
            &ctx(position as u32),
        )?;
        entries.push((
            memory_path("owner", DEFAULT_NAMESPACE, &id)?,
            TaintedValue::pristine(entry),
        ));
    }
    let summaries = crate::memory::consolidation::consolidate(
        &entries,
        "owner",
        DEFAULT_NAMESPACE,
        &ctx(10),
        ConsolidationLimits::default(),
    )
    .await?;
    ensure!(summaries.len() == 1);
    ensure!(entry_text(&summaries[0].1.value) == "[consolidated] a b | a b c d e f");
    entries.reverse();
    let reversed = crate::memory::consolidation::consolidate(
        &entries,
        "owner",
        DEFAULT_NAMESPACE,
        &ctx(11),
        ConsolidationLimits::default(),
    )
    .await?;
    ensure!(entry_text(&reversed[0].1.value) == "[consolidated] e f | a b c d e f");
    let asymmetric = crate::memory::consolidation::consolidate(
        &entries[1..],
        "owner",
        DEFAULT_NAMESPACE,
        &ctx(12),
        ConsolidationLimits::default(),
    )
    .await?;
    ensure!(
        asymmetric.is_empty(),
        "overlap must use the seed's unique word count"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn one_large_pair_yields_each_1024_inspected_tokens() -> anyhow::Result<()> {
    let text = (0..3072)
        .map(|position| format!("word-{position}"))
        .collect::<Vec<_>>()
        .join(" ");
    let words = text.split_whitespace().collect::<BTreeSet<_>>();
    let mut work = TokenWork::default();
    let mut comparison = Box::pin(word_overlap(&words, &words, &mut work));
    let mut task_context = TaskContext::from_waker(Waker::noop());
    for _ in 0..3 {
        ensure!(comparison.as_mut().poll(&mut task_context) == Poll::Pending);
    }
    ensure!(comparison.as_mut().poll(&mut task_context) == Poll::Ready(1.0));
    drop(comparison);
    let short = text.split_whitespace().take(1023).collect::<BTreeSet<_>>();
    let mut comparison = Box::pin(word_overlap(&short, &words, &mut work));
    ensure!(comparison.as_mut().poll(&mut task_context) == Poll::Ready(1.0));
    drop(comparison);
    let one = text.split_whitespace().take(1).collect::<BTreeSet<_>>();
    let mut comparison = Box::pin(word_overlap(&one, &words, &mut work));
    ensure!(comparison.as_mut().poll(&mut task_context) == Poll::Pending);
    ensure!(comparison.as_mut().poll(&mut task_context) == Poll::Ready(1.0));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn repeated_tokens_also_yield_during_word_set_preparation() -> anyhow::Result<()> {
    let content = "coffee ".repeat(2048);
    let entry = build_entry(
        "owner",
        DEFAULT_NAMESPACE,
        "large",
        Tier::Working,
        &BTreeMap::from([("content".into(), Value::string(content))]).into(),
        &ctx(0),
    )?;
    let entries = vec![(
        memory_path("owner", DEFAULT_NAMESPACE, "large")?,
        TaintedValue::pristine(entry),
    )];
    let context = ctx(1);
    let mut consolidation = Box::pin(crate::memory::consolidation::consolidate(
        &entries,
        "owner",
        DEFAULT_NAMESPACE,
        &context,
        ConsolidationLimits::default(),
    ));
    let mut task_context = TaskContext::from_waker(Waker::noop());
    ensure!(consolidation.as_mut().poll(&mut task_context).is_pending());
    ensure!(consolidation.as_mut().poll(&mut task_context).is_pending());
    ensure!(
        matches!(consolidation.as_mut().poll(&mut task_context), Poll::Ready(Ok(summaries)) if summaries.is_empty())
    );
    Ok(())
}
