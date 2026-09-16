//! One State commit is authoritative; the index is an admitted projection.

use super::*;

impl MemoryDriver {
    pub(super) async fn write_indexed_entry(
        &self,
        path: &Path,
        entry: &mut TaintedValue,
        metric: Option<&str>,
        expected_generation: Option<&str>,
        ctx: &DriverContext,
    ) -> Result<bool, ObservedFailure> {
        let request = entry.value.clone();
        let owner = entry_required_str(&entry.value, "owner")?;
        let namespace = entry_required_str(&entry.value, "namespace")?;
        let id = entry_required_str(&entry.value, "id")?.to_owned();
        let generation: ValueText = ctx
            .operation_id
            .map(|operation| blake3::hash(&operation.to_bytes()).to_hex().to_string())
            .ok_or_else(|| invalid("memory writes require an originating OperationId"))?
            .into();
        let current = self
            .state
            .read_tainted(path)
            .await
            .map_err(|error| state_error(error).with_taint(&entry.taint))?;
        let previous = if let Some(current) = &current {
            entry.taint.union(&current.taint);
            validate_stored_entry(path, owner, namespace, &current.value)
                .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
            let indexed = indexed_entry(&current.value)
                .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
            if indexed.generation.as_str() == generation.as_str() {
                // A committed operation owns its original representation. A
                // retry checks its semantic request before repairing projection;
                // it does not invoke a potentially nondeterministic model again.
                if !same_request(&entry.value, &current.value, metric)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?
                {
                    return Err(ObservedFailure::from(invalid(
                        "memory OperationId was reused with a different request",
                    ))
                    .with_taint(&entry.taint));
                }
                entry.value = current.value.clone();
                let (published, observed) = self.reindex_existing(entry).await?;
                entry.taint.union(&observed);
                return Ok(published);
            }
            if expected_generation != Some(indexed.generation.as_str()) {
                return Err(ObservedFailure::from(invalid("memory entry already exists; replacement requires its current expected_generation")).with_taint(&entry.taint));
            }
            Some(indexed)
        } else {
            if expected_generation.is_some() {
                return Err(ObservedFailure::from(invalid(
                    "memory expected_generation does not match an absent entry",
                ))
                .with_taint(&entry.taint));
            }
            None
        };
        let text = entry_text(&entry.value);
        let payload = if text.is_empty() {
            entry_required_field(&entry.value, "content")?.clone()
        } else {
            Value::string(text)
        };
        let embedding = self.embed_for_index(&payload, &entry.taint).await?;
        let space_id = Self::index_space(owner, namespace, &embedding.space_id);
        entry.taint.add(TaintSource::ModelOutput);
        let mut prepared = self
            .index
            .prepare(
                &space_id,
                id.clone(),
                embedding.representation.clone(),
                Some(generation.clone()),
                metric,
                &entry.taint,
            )
            .await?
            .conditional();
        entry.taint.union(prepared.taint());
        let mut index = BTreeMap::from([
            ("id".into(), Value::string(id)),
            ("path".into(), Value::string(path.to_string())),
            ("space_id".into(), Value::string(space_id.clone())),
            ("embedding_space".into(), Value::from(embedding.space_id)),
            (
                "representation".into(),
                embedding.representation.into_value(),
            ),
            ("generation".into(), Value::from(generation.clone())),
            (
                "metric".into(),
                Value::string(metric.unwrap_or("cosine").into()),
            ),
        ]);
        if let Some(model) = embedding.embedding_model {
            index.insert("embedding_model".into(), Value::from(model));
        }
        let mut fields = entry_map(&entry.value)?.clone();
        fields
            .insert("index".into(), Value::map(index))
            .map_err(|error| invalid(format!("memory index metadata: {error}")))?;
        entry.value = Value::from(fields);
        let published = match self
            .state
            .write_cas_tainted(
                path,
                current.map(|current| current.value),
                entry.value.clone(),
                entry.taint.clone(),
            )
            .await
        {
            // The State mutation is authoritative even if its acknowledgement
            // is lost. Projection is rebuilt from the retained representation.
            Ok(commit) => {
                entry.taint.union(&commit.taint);
                prepared.add_taint(&commit.taint);
                self.index.publish(&space_id, prepared).await?
            }
            Err(StateFailure {
                error: StateError::CasFailed { .. },
                taint,
            }) => {
                entry.taint.union(&taint);
                let canonical = self
                    .state
                    .read_tainted(path)
                    .await
                    .map_err(|error| state_error(error).with_taint(&entry.taint))?;
                let Some(canonical) = canonical else {
                    return Err(ObservedFailure::from(invalid(
                        "memory record disappeared while confirming its existing value",
                    ))
                    .with_taint(&entry.taint));
                };
                entry.taint.union(&canonical.taint);
                let current_generation = indexed_entry(&canonical.value)
                    .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?
                    .generation;
                if current_generation.as_str() != generation.as_str()
                    || !same_request(&request, &canonical.value, metric)
                        .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?
                {
                    return Err(ObservedFailure::from(invalid(
                        "memory record changed during conditional replacement",
                    ))
                    .with_taint(&entry.taint));
                }
                // Concurrent retries can receive different model output. Adopt
                // the first committed representation for the same semantic
                // operation and conditionally project that exact State record.
                entry.value = canonical.value;
                let (published, observed) = self.reindex_existing(entry).await?;
                entry.taint.union(&observed);
                published
            }
            Err(error) => {
                return Err(state_error(error).with_taint(&entry.taint));
            }
        };
        if let Some(previous) = previous {
            self.index
                .delete_generation(&previous.space_id, &previous.id, Some(&previous.generation))
                .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
        }
        Ok(published)
    }

    pub(super) async fn reindex_existing(
        &self,
        entry: &TaintedValue,
    ) -> Result<(bool, TaintSet), ObservedFailure> {
        let indexed = indexed_entry(&entry.value)
            .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
        let metadata = entry_required_map(&entry.value, "index")
            .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
        let representation = metadata.get("representation").cloned().ok_or_else(|| {
            ObservedFailure::from(invalid("stored memory has no retrieval representation"))
                .with_taint(&entry.taint)
        })?;
        let representation = EmbeddingRepresentation::from_value(representation)
            .map_err(|error| ObservedFailure::from(invalid(error)).with_taint(&entry.taint))?;
        let metric = metadata
            .get("metric")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ObservedFailure::from(invalid("stored memory has no retrieval metric"))
                    .with_taint(&entry.taint)
            })?;
        let mut prepared = self
            .index
            .prepare(
                &indexed.space_id,
                indexed.id,
                representation,
                Some(indexed.generation),
                Some(metric),
                &entry.taint,
            )
            .await?
            .conditional();
        let path = entry_path(&entry.value)
            .map_err(|error| ObservedFailure::from(error).with_taint(&entry.taint))?;
        let mut observed = prepared.taint().clone();
        let current = self
            .state
            .read_tainted(&path)
            .await
            .map_err(|error| state_error(error).with_taint(&observed))?;
        let Some(current) = current else {
            return Ok((false, observed));
        };
        observed.union(&current.taint);
        if current.value != entry.value {
            return Ok((false, observed));
        }
        prepared.add_taint(&current.taint);
        let published = self.index.publish(&indexed.space_id, prepared).await?;
        Ok((published, observed))
    }

    pub(super) async fn rebuild_namespace(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<(i64, TaintSet), ObservedFailure> {
        let mut pages = scan::NamespaceScan::new(&self.state, namespace_path(owner, namespace)?);
        let mut taint = TaintSet::pristine();
        let mut count = 0_i64;
        while let Some(page) = pages
            .next()
            .await
            .map_err(|error| state_error(error).with_taint(&taint))?
        {
            taint.union(&page.taint);
            for (path, mut entry) in page.entries {
                loop {
                    taint.union(&entry.taint);
                    validate_stored_entry(&path, owner, namespace, &entry.value)
                        .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
                    let (published, observed) = self
                        .reindex_existing(&entry)
                        .await
                        .map_err(|error| error.with_taint(&taint))?;
                    taint.union(&observed);
                    if published {
                        count = count.saturating_add(1);
                        break;
                    }
                    let Some(current) = self
                        .state
                        .read_tainted(&path)
                        .await
                        .map_err(|error| state_error(error).with_taint(&taint))?
                    else {
                        break;
                    };
                    entry = current;
                    tokio::task::yield_now().await;
                }
            }
        }
        Ok((count, taint))
    }
}

fn same_request(
    request: &Value,
    stored: &Value,
    metric: Option<&str>,
) -> Result<bool, DriverError> {
    let request = entry_map(request)?;
    let stored_fields = entry_map(stored)?;
    let stored_metric = entry_required_map(stored, "index")?
        .get("metric")
        .and_then(Value::as_str);
    Ok(stored_fields.len() == request.len() + 1
        && request
            .iter()
            .all(|(key, value)| stored_fields.get(key) == Some(value))
        && stored_metric == Some(metric.unwrap_or("cosine")))
}
