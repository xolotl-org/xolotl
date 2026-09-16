//! Generation-checked recall and explicit reconstruction of missing projections.

use super::*;

impl MemoryDriver {
    pub(super) async fn recall_from_input(
        &self,
        input: &ValueMap,
        input_taint: &TaintSet,
    ) -> Result<DriverOutput, ObservedFailure> {
        let owner = required_segment(input, "owner")?;
        let namespace = namespace_from_input(input)?;
        let query = required_text(input, "query")?;
        let k = optional_nonnegative_usize(input, "k", 5)?;
        let kind = optional_segment(input, "kind")?;
        let consistency = optional_string(input, "consistency")?.unwrap_or("indexed");
        if !matches!(consistency, "indexed" | "reconcile") {
            return Err(invalid("memory recall consistency must be indexed or reconcile").into());
        }
        let metric = optional_string(input, "metric")?;
        let mode = optional_string(input, "mode")?.unwrap_or("auto");
        if !matches!(mode, "auto" | "exact") {
            return Err(invalid("memory search mode must be auto or exact").into());
        }
        if k == 0 {
            return Ok(DriverOutput::new(Outcome::Done(Value::list(Vec::new()))));
        }
        let mut taint = input_taint.clone();
        if consistency == "reconcile" {
            let (_, observed) = self.rebuild_namespace(&owner, &namespace).await?;
            taint.union(&observed);
        }
        let embedding = self
            .embed_for_index(&Value::from(query), input_taint)
            .await
            .map_err(|error| error.with_taint(&taint))?;
        taint.add(TaintSource::ModelOutput);
        let space_id = Self::index_space(&owner, &namespace, &embedding.space_id);
        let mut search = BTreeMap::from([
            ("space_id".into(), Value::string(space_id.clone())),
            (
                "representation".into(),
                embedding.representation.into_value(),
            ),
            ("k".into(), Value::integer(overfetch(k))),
            ("mode".into(), Value::string(mode.into())),
        ]);
        if let Some(metric) = metric {
            search.insert("metric".into(), Value::string(metric.into()));
        }
        let search: ValueMap = search.into();
        loop {
            let output = self
                .index
                .search_or_empty(&search, input_taint)
                .await
                .map_err(|error| error.with_taint(&taint))?;
            taint.union(&output.taint);
            let hits = done(output, &taint, "index search")?
                .into_list()
                .ok_or_else(|| failure("index search must return a list", &taint))?;
            let mut entries = BTreeMap::new();
            let mut signals = Vec::new();
            let mut repaired = false;
            for hit in &hits {
                let fields = hit
                    .as_map()
                    .ok_or_else(|| failure("index hit must be a map", &taint))?;
                let id = fields
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| failure("index hit missing id", &taint))?;
                let generation = fields.get("generation").and_then(Value::as_str);
                let score = fields
                    .get("sim")
                    .and_then(|value| match value.view() {
                        ValueView::Float(FloatBits(value)) => Some(value),
                        ValueView::Int(value) => Some(value as f64),
                        _ => None,
                    })
                    .ok_or_else(|| failure("index hit missing numeric score", &taint))?;
                let path = memory_path(&owner, &namespace, id)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                let current = self
                    .state
                    .read_tainted(&path)
                    .await
                    .map_err(|error| state_error(error).with_taint(&taint))?;
                let Some(current) = current else {
                    if let Some(generation) = generation {
                        self.index
                            .delete_generation(&space_id, id, Some(generation))
                            .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                    } else {
                        return Err(failure(
                            "memory index contains an unversioned foreign entry",
                            &taint,
                        ));
                    }
                    repaired = true;
                    continue;
                };
                taint.union(&current.taint);
                validate_stored_entry(&path, &owner, &namespace, &current.value)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                let indexed = indexed_entry(&current.value)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                if generation != Some(indexed.generation.as_str()) || indexed.space_id != space_id {
                    if let Some(generation) = generation {
                        self.index
                            .delete_generation(&space_id, id, Some(generation))
                            .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                    }
                    let (_, observed) = self
                        .reindex_existing(&current)
                        .await
                        .map_err(|error| error.with_taint(&taint))?;
                    taint.union(&observed);
                    repaired = true;
                    continue;
                }
                if kind
                    .as_deref()
                    .is_some_and(|kind| entry_kind(&current.value) != Some(kind))
                {
                    continue;
                }
                let mut signal = BTreeMap::from([
                    ("id".into(), Value::string(id.to_string())),
                    ("semantic_sim".into(), Value::float(FloatBits(score))),
                    ("recency".into(), Value::float(FloatBits(0.0))),
                ]);
                for field in ["weight", "confidence"] {
                    if let Some(value) = entry_field(&current.value, field) {
                        signal.insert(field.into(), value.clone());
                    }
                }
                signals.push(Value::map(signal));
                entries.insert(id.to_string(), current.value);
            }
            if repaired {
                // Retry the query after observed stale candidates were removed or
                // replaced. Never pair an old score with the new State record.
                tokio::task::yield_now().await;
                continue;
            }
            if signals.is_empty() {
                return Ok(
                    DriverOutput::new(Outcome::Done(Value::list(Vec::new()))).with_taint(taint)
                );
            }
            let ranking = self
                .ranker
                .call(
                    MethodId::new(0),
                    Value::map(BTreeMap::from([("signals".into(), Value::list(signals))])),
                    OutputMode::Unary,
                    &internal_ctx(&taint),
                )
                .await
                .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
            taint.union(&ranking.taint);
            let ranked = done(ranking, &taint, "ranker")?
                .into_list()
                .ok_or_else(|| failure("ranker must return a list", &taint))?;
            let mut result = Vec::new();
            for ranked in &ranked {
                if result.len() == k {
                    break;
                }
                if let Some(id) = ranked
                    .as_map()
                    .and_then(|fields| fields.get("id"))
                    .and_then(Value::as_str)
                    && let Some(entry) = entries.remove(id)
                {
                    result.push(entry);
                }
            }
            return Ok(DriverOutput::new(Outcome::Done(Value::list(result))).with_taint(taint));
        }
    }
}

fn failure(message: &str, taint: &TaintSet) -> ObservedFailure {
    ObservedFailure::from(DriverError::Other(message.into())).with_taint(taint)
}

fn done(output: DriverOutput, taint: &TaintSet, component: &str) -> Result<Value, ObservedFailure> {
    match output.outcome {
        Outcome::Done(value) => Ok(value),
        other => Err(failure(
            &format!("{component} returned an unsuccessful outcome: {other:?}"),
            taint,
        )),
    }
}
