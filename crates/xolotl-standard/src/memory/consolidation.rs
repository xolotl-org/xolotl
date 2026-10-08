//! Bounded namespace admission and seed-based asymmetric text clustering.

use super::*;

#[derive(Clone, Copy)]
pub(crate) struct ConsolidationLimits {
    pub(crate) records: NonZeroUsize,
    pub(crate) encoded_bytes: NonZeroUsize,
    pub(crate) text_bytes: NonZeroUsize,
}

impl Default for ConsolidationLimits {
    fn default() -> Self {
        Self {
            records: NonZeroUsize::MIN.saturating_add(1023),
            encoded_bytes: NonZeroUsize::MIN.saturating_add(16 * 1024 * 1024 - 1),
            text_bytes: NonZeroUsize::MIN.saturating_add(4 * 1024 * 1024 - 1),
        }
    }
}

#[derive(Default)]
pub(super) struct TokenWork(usize);

impl TokenWork {
    async fn inspect(&mut self) {
        self.0 += 1;
        if self.0 == 1024 {
            self.0 = 0;
            tokio::task::yield_now().await;
        }
    }
}

pub(super) async fn consolidate(
    entries: &[(Path, TaintedValue)],
    owner: &str,
    namespace: &str,
    ctx: &DriverContext,
    limits: ConsolidationLimits,
) -> Result<Vec<(Path, TaintedValue)>, DriverError> {
    const THRESHOLD: f64 = 0.34;
    let mut candidates = Vec::new();
    let mut texts = Vec::new();
    let mut remaining = limits.text_bytes.get();
    for (_, entry) in entries {
        let text = text::entry_text_bounded(&entry.value, remaining)
            .ok_or_else(|| invalid("memory consolidation text byte limit exceeded"))?;
        remaining -= text.len();
        if matches!(
            entry_field(&entry.value, "tier").and_then(Value::as_str),
            Some("working" | "recent")
        ) {
            candidates.push(entry);
            texts.push(text);
        }
    }
    let mut work = TokenWork::default();
    let mut words = Vec::with_capacity(texts.len());
    for text in &texts {
        let mut set = BTreeSet::new();
        for token in text.split_whitespace() {
            set.insert(token);
            work.inspect().await;
        }
        words.push(set);
    }
    let mut used = vec![false; texts.len()];
    let mut summaries = Vec::new();
    for seed in 0..texts.len() {
        if used[seed] || texts[seed].is_empty() {
            continue;
        }
        let mut cluster_texts = vec![texts[seed].as_str()];
        let mut source_ids = vec![entry_required_str(&candidates[seed].value, "id")?.to_string()];
        let mut low_trust = entry_required_bool(&candidates[seed].value, "low_trust")?;
        let mut taint = ctx.taint.clone();
        taint.union(&candidates[seed].taint);
        used[seed] = true;
        for candidate in (seed + 1)..texts.len() {
            if used[candidate] {
                continue;
            }
            let score = word_overlap(&words[seed], &words[candidate], &mut work).await;
            if score >= THRESHOLD {
                cluster_texts.push(texts[candidate].as_str());
                source_ids
                    .push(entry_required_str(&candidates[candidate].value, "id")?.to_string());
                low_trust |= entry_required_bool(&candidates[candidate].value, "low_trust")?;
                taint.union(&candidates[candidate].taint);
                used[candidate] = true;
            }
        }
        if cluster_texts.len() < 2 {
            continue;
        }
        let summary = format!("[consolidated] {}", cluster_texts.join(" | "));
        let id = summary_id(owner, namespace, &source_ids, ctx)?;
        let path = memory_path(owner, namespace, &id)?;
        let mut input = BTreeMap::new();
        input.insert("content".into(), Value::string(summary));
        input.insert("kind".into(), Value::string("summary".into()));
        input.insert("weight".into(), Value::float(FloatBits(1.5)));
        input.insert("confidence".into(), Value::float(FloatBits(1.0)));
        input.insert("low_trust".into(), Value::boolean(low_trust));
        let mut facets = BTreeMap::new();
        facets.insert(
            "consolidated_count".into(),
            Value::integer(cluster_texts.len() as i64),
        );
        input.insert("facets".into(), Value::map(facets));
        let mut links = BTreeMap::new();
        links.insert(
            "derived_from".into(),
            Value::list(source_ids.into_iter().map(Value::string).collect()),
        );
        input.insert("links".into(), Value::map(links));
        summaries.push((
            path,
            TaintedValue::new(
                build_entry(owner, namespace, &id, Tier::LongTerm, &input.into(), ctx)?,
                taint,
            ),
        ));
    }
    Ok(summaries)
}

pub(super) async fn word_overlap(
    seed: &BTreeSet<&str>,
    candidate: &BTreeSet<&str>,
    work: &mut TokenWork,
) -> f64 {
    if seed.is_empty() {
        return 0.0;
    }
    let mut hits = 0;
    for token in seed {
        hits += usize::from(candidate.contains(token));
        work.inspect().await;
    }
    hits as f64 / seed.len() as f64
}
