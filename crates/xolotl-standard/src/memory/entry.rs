//! Stored memory envelopes and identity validation.

use super::*;

pub(super) fn build_entry(
    owner: &str,
    namespace: &str,
    id: &str,
    tier: Tier,
    input: &ValueMap,
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
            && facets.get(key).is_none()
        {
            facets
                .insert(key.to_string(), value.clone())
                .map_err(|error| {
                    DriverError::InvalidInput(format!("memory facets update failed: {error}"))
                })?;
        }
    }
    let low_trust = ctx.taint.has_untrusted_content() || optional_bool(input, "low_trust", false)?;
    let mut entry = BTreeMap::new();
    entry.insert("id".into(), Value::string(id.to_string()));
    entry.insert("owner".into(), Value::string(owner.to_string()));
    entry.insert("namespace".into(), Value::string(namespace.to_string()));
    entry.insert("kind".into(), Value::string(kind));
    entry.insert("content".into(), content);
    entry.insert("facets".into(), Value::from(facets));
    entry.insert("tier".into(), Value::string(tier.as_str().to_string()));
    entry.insert(
        "weight".into(),
        Value::float(FloatBits(optional_f64(input, "weight", 1.0)?)),
    );
    entry.insert(
        "confidence".into(),
        Value::float(FloatBits(optional_f64(input, "confidence", 1.0)?)),
    );
    entry.insert("access_count".into(), Value::integer(0));
    entry.insert("low_trust".into(), Value::boolean(low_trust));
    entry.insert(
        "links".into(),
        Value::from(optional_map(input, "links")?.cloned().unwrap_or_default()),
    );
    entry.insert(
        "provenance".into(),
        input.get("provenance").cloned().unwrap_or(Value::null()),
    );
    entry.insert("version".into(), Value::integer(1));
    Ok(Value::map(entry))
}

pub(super) fn namespace_from_input(input: &ValueMap) -> Result<String, DriverError> {
    optional_segment(input, "namespace")
        .map(|namespace| namespace.unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()))
}

pub(super) fn id_from_input(
    input: &ValueMap,
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

pub(super) fn summary_id(
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

pub(super) fn tier_from_input(input: &ValueMap) -> Result<Tier, DriverError> {
    match input.get("tier").and_then(Value::as_str) {
        Some("working") | None => Ok(Tier::Working),
        Some("recent") => Ok(Tier::Recent),
        Some("long_term") => Ok(Tier::LongTerm),
        Some("archive") => Ok(Tier::Archive),
        Some(other) => Err(DriverError::InvalidInput(format!(
            "unknown memory tier {other:?}"
        ))),
    }
}

pub(super) fn memory_path(owner: &str, namespace: &str, id: &str) -> Result<Path, DriverError> {
    namespace_path(owner, namespace)?
        .try_push_literal(id)
        .map_err(|e| DriverError::InvalidInput(format!("invalid memory id {id:?}: {e}")))
}

pub(super) fn namespace_path(owner: &str, namespace: &str) -> Result<Path, DriverError> {
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

pub(super) fn required_segment(
    input: &ValueMap,
    field: &'static str,
) -> Result<String, DriverError> {
    let value = required_text(input, field)?;
    validate_segment(field, &value)
}

pub(super) fn optional_segment(
    input: &ValueMap,
    field: &'static str,
) -> Result<Option<String>, DriverError> {
    optional_string(input, field).and_then(|value| match value {
        Some(value) => validate_segment(field, value).map(Some),
        None => Ok(None),
    })
}

pub(super) fn validate_segment(field: &'static str, value: &str) -> Result<String, DriverError> {
    Path::try_new("state")
        .and_then(|path| path.try_push_literal(value))
        .map_err(|e| DriverError::InvalidInput(format!("{field} is not a safe segment: {e}")))?;
    Ok(value.to_string())
}

pub(super) fn required_text(
    input: &ValueMap,
    field: &'static str,
) -> Result<ValueText, DriverError> {
    let value = input.get(field).ok_or_else(|| {
        DriverError::InvalidInput(format!("memory input missing required field {field}"))
    })?;
    let text = value
        .clone()
        .into_text()
        .ok_or_else(|| DriverError::InvalidInput(format!("{field} must be a string")))?;
    if text.is_empty() {
        return Err(DriverError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    Ok(text)
}

pub(super) fn optional_string<'a>(
    input: &'a ValueMap,
    field: &'static str,
) -> Result<Option<&'a str>, DriverError> {
    match input.get(field).map(Value::view) {
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(Some(value)),
        Some(ValueView::Str(_)) => Err(DriverError::InvalidInput(format!(
            "{field} must not be empty"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{field} must be a string"
        ))),
        None => Ok(None),
    }
}

pub(super) fn optional_map<'a>(
    input: &'a ValueMap,
    field: &'static str,
) -> Result<Option<&'a ValueMap>, DriverError> {
    match input.get(field).map(Value::view) {
        Some(ValueView::Map(map)) => Ok(Some(map)),
        Some(_) => Err(DriverError::InvalidInput(format!("{field} must be a map"))),
        None => Ok(None),
    }
}

pub(super) fn optional_bool(
    input: &ValueMap,
    field: &'static str,
    default: bool,
) -> Result<bool, DriverError> {
    match input.get(field).map(Value::view) {
        Some(ValueView::Bool(value)) => Ok(value),
        Some(_) => Err(DriverError::InvalidInput(format!("{field} must be a bool"))),
        None => Ok(default),
    }
}

pub(super) fn optional_f64(
    input: &ValueMap,
    field: &'static str,
    default: f64,
) -> Result<f64, DriverError> {
    match input.get(field).map(Value::view) {
        Some(ValueView::Float(FloatBits(value))) if value.is_finite() => Ok(value),
        Some(ValueView::Int(value)) => Ok(value as f64),
        Some(ValueView::Float(_)) => {
            Err(DriverError::InvalidInput(format!("{field} must be finite")))
        }
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{field} must be numeric"
        ))),
        None => Ok(default),
    }
}

pub(super) fn optional_nonnegative_usize(
    input: &ValueMap,
    field: &'static str,
    default: usize,
) -> Result<usize, DriverError> {
    match input.get(field).map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => usize::try_from(value).map_err(|_error| {
            DriverError::InvalidInput(format!("{field} is too large for this platform"))
        }),
        Some(ValueView::Int(_)) => Err(DriverError::InvalidInput(format!(
            "{field} must be nonnegative"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{field} must be an integer"
        ))),
        None => Ok(default),
    }
}

pub(super) fn validate_stored_entry(
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
    let metadata = entry_required_map(entry, "index")?;
    let embedding_space = metadata
        .get("embedding_space")
        .and_then(Value::as_str)
        .filter(|space| !space.is_empty())
        .ok_or_else(|| invalid("stored memory has no embedding space"))?;
    if metadata.get("path").and_then(Value::as_str) != Some(path.to_string().as_str())
        || indexed.space_id != MemoryDriver::index_space(owner, namespace, embedding_space)
    {
        return Err(invalid(
            "stored memory index identity does not match its State record",
        ));
    }
    let representation = metadata
        .get("representation")
        .cloned()
        .ok_or_else(|| invalid("stored memory has no retrieval representation"))?;
    EmbeddingRepresentation::from_value(representation).map_err(invalid)?;
    if !matches!(
        metadata.get("metric").and_then(Value::as_str),
        Some("cosine" | "dot" | "negative_squared_euclidean" | "mean_max_cosine")
    ) {
        return Err(invalid("stored memory has no supported retrieval metric"));
    }
    Ok(())
}

pub(super) fn entry_map(entry: &Value) -> Result<&ValueMap, DriverError> {
    entry
        .as_map()
        .ok_or_else(|| DriverError::Other("memory entry must be a map".into()))
}

pub(super) fn entry_required_str<'a>(
    entry: &'a Value,
    field: &'static str,
) -> Result<&'a str, DriverError> {
    match entry_map(entry)?.get(field).map(Value::view) {
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(value),
        Some(ValueView::Str(_)) => Err(DriverError::Other(format!(
            "memory entry field {field} must not be empty"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "memory entry field {field} must be string"
        ))),
        None => Err(DriverError::Other(format!("memory entry missing {field}"))),
    }
}

pub(super) fn entry_required_field<'a>(
    entry: &'a Value,
    field: &'static str,
) -> Result<&'a Value, DriverError> {
    entry_map(entry)?
        .get(field)
        .ok_or_else(|| DriverError::Other(format!("memory entry missing {field}")))
}

pub(super) fn entry_required_map<'a>(
    entry: &'a Value,
    field: &'static str,
) -> Result<&'a ValueMap, DriverError> {
    match entry_required_field(entry, field)?.view() {
        ValueView::Map(map) => Ok(map),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be map"
        ))),
    }
}

pub(super) fn entry_required_bool(entry: &Value, field: &'static str) -> Result<bool, DriverError> {
    match entry_required_field(entry, field)?.view() {
        ValueView::Bool(value) => Ok(value),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be bool"
        ))),
    }
}

pub(super) fn entry_required_number(entry: &Value, field: &'static str) -> Result<(), DriverError> {
    match entry_required_field(entry, field)?.view() {
        ValueView::Int(_) => Ok(()),
        ValueView::Float(FloatBits(value)) if value.is_finite() => Ok(()),
        ValueView::Float(_) => Err(DriverError::Other(format!(
            "memory entry field {field} must be finite"
        ))),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be numeric"
        ))),
    }
}

pub(super) fn entry_required_int(entry: &Value, field: &'static str) -> Result<i64, DriverError> {
    match entry_required_field(entry, field)?.view() {
        ValueView::Int(value) => Ok(value),
        _ => Err(DriverError::Other(format!(
            "memory entry field {field} must be integer"
        ))),
    }
}

pub(super) fn validate_stored_tier(tier: &str) -> Result<(), DriverError> {
    match tier {
        "working" | "recent" | "long_term" | "archive" => Ok(()),
        other => Err(DriverError::Other(format!(
            "memory entry has unknown tier {other:?}"
        ))),
    }
}

pub(super) fn entry_field<'a>(entry: &'a Value, field: &str) -> Option<&'a Value> {
    entry.as_map().and_then(|map| map.get(field))
}

pub(super) fn entry_kind(entry: &Value) -> Option<&str> {
    entry_field(entry, "kind").and_then(Value::as_str)
}

pub(super) fn entry_path(entry: &Value) -> Result<Path, DriverError> {
    let owner = entry_required_str(entry, "owner")?;
    let namespace = entry_required_str(entry, "namespace")?;
    let id = entry_required_str(entry, "id")?;
    memory_path(owner, namespace, id)
}

pub(super) fn indexed_entry(entry: &Value) -> Result<IndexedEntry, DriverError> {
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
    let generation = index
        .get("generation")
        .cloned()
        .and_then(Value::into_text)
        .filter(|generation| !generation.is_empty())
        .ok_or_else(|| DriverError::Other("memory index metadata missing generation".into()))?;
    Ok(IndexedEntry {
        id: id.to_string(),
        space_id: space_id.to_string(),
        generation,
    })
}

pub(super) fn store_result(id: &str, path: &Path, indexed: bool, generation: ValueText) -> Value {
    let mut result = BTreeMap::new();
    result.insert("id".into(), Value::string(id.to_string()));
    result.insert("path".into(), Value::string(path.to_string()));
    result.insert("indexed".into(), Value::boolean(indexed));
    result.insert("generation".into(), Value::from(generation));
    Value::map(result)
}

pub(super) fn hash_operation_id(hasher: &mut blake3::Hasher, op_id: xolotl_types::OperationId) {
    hasher.update(&op_id.to_bytes());
}

pub(super) fn overlap(query: &str, text: &str) -> f64 {
    let q: BTreeSet<&str> = query.split_whitespace().collect();
    if q.is_empty() {
        return 0.0;
    }
    let t: BTreeSet<&str> = text.split_whitespace().collect();
    let hits = q.iter().filter(|w| t.contains(*w)).count();
    hits as f64 / q.len() as f64
}

pub(super) fn overfetch(k: usize) -> i64 {
    i64::try_from(k.saturating_mul(8)).unwrap_or(i64::MAX)
}
