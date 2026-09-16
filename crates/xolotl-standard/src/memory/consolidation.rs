//! Namespace consolidation over admitted stored entries.

use super::*;

pub(super) fn consolidate(
    entries: &[(Path, TaintedValue)],
    owner: &str,
    namespace: &str,
    ctx: &DriverContext,
) -> Result<Vec<(Path, TaintedValue)>, DriverError> {
    const THRESHOLD: f64 = 0.34;
    let candidates: Vec<&TaintedValue> = entries
        .iter()
        .map(|(_, entry)| entry)
        .filter(|entry| {
            matches!(
                entry_field(&entry.value, "tier").and_then(Value::as_str),
                Some("working" | "recent")
            )
        })
        .collect();
    let texts: Vec<String> = candidates
        .iter()
        .map(|entry| entry_text(&entry.value))
        .collect();
    let mut used = vec![false; texts.len()];
    let mut summaries = Vec::new();
    for i in 0..texts.len() {
        if used[i] || texts[i].is_empty() {
            continue;
        }
        let mut cluster_texts = vec![texts[i].as_str()];
        let mut source_ids = vec![entry_required_str(&candidates[i].value, "id")?.to_string()];
        let mut low_trust = entry_required_bool(&candidates[i].value, "low_trust")?;
        let mut taint = ctx.taint.clone();
        taint.union(&candidates[i].taint);
        used[i] = true;
        for j in (i + 1)..texts.len() {
            if !used[j] && overlap(&texts[i], &texts[j]) >= THRESHOLD {
                cluster_texts.push(texts[j].as_str());
                source_ids.push(entry_required_str(&candidates[j].value, "id")?.to_string());
                low_trust |= entry_required_bool(&candidates[j].value, "low_trust")?;
                taint.union(&candidates[j].taint);
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
