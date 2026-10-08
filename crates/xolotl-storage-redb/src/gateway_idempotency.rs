use std::sync::Arc;

use crate::database::Database;
use async_trait::async_trait;
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use tokio::sync::oneshot;
use xolotl_gateway::{
    GatewayError, GatewayEvidenceNamespace, GatewayIdempotencyLimits, GatewayIdempotencyRecord,
    GatewayIdempotencyStore, GatewayIdempotencyUsage,
};
use xolotl_kernel::host::{BlockingSpawnError, BlockingSpawner};
use xolotl_types::{TaintedValue, Value};

use crate::{blocking::TrackedBlockingSpawner, schema::STATE_VALUES_TABLE};

const RECORDS: TableDefinition<&str, (u64, &[u8])> =
    TableDefinition::new("gateway_idempotency_records_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("gateway_idempotency_meta_v1");
const LEGACY_PREFIX: &str = "state://gateway/idempotency/";
const NAMESPACE_WORDS: [&str; 4] = [
    "evidence_namespace_0",
    "evidence_namespace_1",
    "evidence_namespace_2",
    "evidence_namespace_3",
];

/// Bounded durable request evidence, independent of ordinary State and history.
/// The monotonic store-wide retry barrier and certain-detail reclamation commit
/// in one transaction. Reopen preserves closure; missing barrier metadata fails
/// closed. Format v1 creates a nonzero evidence namespace once for a fresh ledger;
/// adapters, clones and reopens share that persisted identity. Unsupported formats and
/// missing or invalid identity metadata are rejected without regenerating it.
/// Copying a database preserves its identity and is not rollback-resistant recovery.
#[derive(Clone)]
pub struct RedbGatewayIdempotencyStore {
    db: Arc<Database>,
    blocking_spawner: Arc<TrackedBlockingSpawner>,
    limits: GatewayIdempotencyLimits,
    evidence_namespace: GatewayEvidenceNamespace,
}

impl RedbGatewayIdempotencyStore {
    pub(crate) fn new(
        db: Arc<Database>,
        blocking_spawner: Arc<TrackedBlockingSpawner>,
        limits: GatewayIdempotencyLimits,
    ) -> Result<Self, GatewayError> {
        limits.validate()?;
        let transaction = db.begin_write().map_err(storage_error)?;
        let mut records_exist = false;
        let mut meta_exists = false;
        for table in transaction.list_tables().map_err(storage_error)? {
            records_exist |= table.name() == RECORDS.name();
            meta_exists |= table.name() == META.name();
        }
        if records_exist != meta_exists {
            return Err(rejected("Gateway idempotency tables missing"));
        }
        {
            let state = transaction
                .open_table(STATE_VALUES_TABLE)
                .map_err(storage_error)?;
            if let Some(entry) = state.range(LEGACY_PREFIX..).map_err(storage_error)?.next() {
                let (key, _) = entry.map_err(storage_error)?;
                if key.value().starts_with(LEGACY_PREFIX) {
                    return Err(rejected("unsupported legacy Gateway idempotency records"));
                }
            }
        }
        let evidence_namespace = {
            let rows = transaction.open_table(RECORDS).map_err(storage_error)?;
            let mut meta = transaction.open_table(META).map_err(storage_error)?;
            let version = meta
                .get("version")
                .map_err(storage_error)?
                .map(|row| row.value());
            match version {
                None => {
                    if records_exist
                        || !rows.is_empty().map_err(storage_error)?
                        || !meta.is_empty().map_err(storage_error)?
                    {
                        return Err(rejected("idempotency metadata missing"));
                    }
                    for (key, value) in [
                        ("version", 1),
                        ("retry_epoch", 0),
                        ("max_records", as_u64(limits.max_records.get())?),
                        ("max_bytes", as_u64(limits.max_bytes.get())?),
                        ("max_record_bytes", as_u64(limits.max_record_bytes.get())?),
                        ("records", 0),
                        ("bytes", 0),
                    ] {
                        meta.insert(key, value).map_err(storage_error)?;
                    }
                    let namespace = GatewayEvidenceNamespace::generate()?;
                    for (index, key) in NAMESPACE_WORDS.into_iter().enumerate() {
                        let mut word = [0; 8];
                        word.copy_from_slice(&namespace.as_bytes()[index * 8..(index + 1) * 8]);
                        meta.insert(key, u64::from_be_bytes(word))
                            .map_err(storage_error)?;
                    }
                    namespace
                }
                Some(1) => {
                    for (key, limit) in [
                        ("max_records", limits.max_records.get()),
                        ("max_bytes", limits.max_bytes.get()),
                        ("max_record_bytes", limits.max_record_bytes.get()),
                    ] {
                        if counter(&meta, key)? != limit {
                            return Err(rejected(
                                "Gateway idempotency limits differ from durable limits",
                            ));
                        }
                    }
                    let usage = read_usage(&meta, limits)?;
                    if rows.len().map_err(storage_error)? != as_u64(usage.records)? {
                        return Err(rejected("idempotency record accounting mismatch"));
                    }
                    retry_epoch(&meta)?;
                    let mut bytes = [0; 32];
                    for (index, key) in NAMESPACE_WORDS.into_iter().enumerate() {
                        let word = meta
                            .get(key)
                            .map_err(storage_error)?
                            .ok_or_else(|| rejected("idempotency evidence namespace missing"))?
                            .value();
                        bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
                    }
                    GatewayEvidenceNamespace::from_bytes(bytes)?
                }
                Some(_) => return Err(rejected("unsupported Gateway idempotency format")),
            }
        };
        transaction.commit().map_err(commit_error)?;
        Ok(Self {
            db,
            blocking_spawner,
            limits,
            evidence_namespace,
        })
    }

    async fn run<Output: Send + 'static>(
        &self,
        operation: impl FnOnce(Arc<Database>, GatewayIdempotencyLimits) -> Result<Output, GatewayError>
        + Send
        + 'static,
    ) -> Result<Output, GatewayError> {
        let db = self.db.clone();
        let limits = self.limits;
        let (sender, receiver) = oneshot::channel();
        self.blocking_spawner
            .spawn(Box::new(move || {
                drop(sender.send(operation(db, limits)));
            }))
            .map_err(|error| match error {
                BlockingSpawnError::AtCapacity => GatewayError::LimitExceeded(
                    "Gateway idempotency blocking capacity exhausted before admission".into(),
                ),
                BlockingSpawnError::Unavailable => GatewayError::LimitExceeded(
                    "Gateway idempotency blocking host unavailable before admission".into(),
                ),
            })?;
        receiver.await.map_err(|_error| {
            GatewayError::Indeterminate(
                "accepted Gateway idempotency operation lost its worker result".into(),
            )
        })?
    }

    async fn change(&self, key: &str, expected: Value, change: Change) -> Result<(), GatewayError> {
        validate_key(key)?;
        let key = key.to_owned();
        self.run(move |db, limits| {
            let original = load(&db, &key, limits)?
                .ok_or_else(|| conflict("idempotency record absent during settlement"))?;
            let observed = original.observe()?;
            if observed.value != expected {
                return Err(conflict("idempotency record changed during settlement"));
            }
            let replacement = match change {
                Change::Complete(mut value) => {
                    require_pending(&observed.value)?;
                    value.taint.union(&observed.taint);
                    Some(GatewayIdempotencyRecord::completed(value, limits)?)
                }
                Change::Release => {
                    require_pending(&observed.value)?;
                    None
                }
                Change::Retire => Some(original.retired(limits)?),
            };
            if let Some(replacement) = &replacement {
                replacement.validate_binding(&key)?;
                replacement.validate_replacement(&expected)?;
            }
            let transaction = db.begin_write().map_err(storage_error)?;
            {
                let mut rows = transaction.open_table(RECORDS).map_err(storage_error)?;
                let mut meta = transaction.open_table(META).map_err(storage_error)?;
                let record = rows
                    .get(key.as_str())
                    .map_err(storage_error)?
                    .map(|row| {
                        let (charge, encoded) = row.value();
                        decode(&key, encoded, charge, limits)
                    })
                    .transpose()?
                    .ok_or_else(|| conflict("idempotency record absent during settlement"))?;
                let actual = record.observe()?;
                if actual.value != expected {
                    return Err(conflict("idempotency record changed during settlement"));
                }
                let replacement = match replacement {
                    Some(replacement) if actual.taint != observed.taint => {
                        let mut value = replacement.observe()?;
                        if value
                            .value
                            .as_map()
                            .and_then(|map| map.get("state"))
                            .and_then(Value::as_str)
                            == Some("committed")
                        {
                            value.taint.union(&actual.taint);
                            Some(GatewayIdempotencyRecord::completed(value, limits)?)
                        } else {
                            Some(record.retired(limits)?)
                        }
                    }
                    replacement => replacement,
                };
                if let Some(replacement) = &replacement {
                    replacement.validate_binding(&key)?;
                    replacement.validate_replacement(&expected)?;
                }
                let usage = read_usage(&meta, limits)?;
                let bytes = usage
                    .bytes
                    .checked_sub(record.charged_bytes())
                    .and_then(|bytes| {
                        bytes.checked_add(
                            replacement
                                .as_ref()
                                .map_or(0, GatewayIdempotencyRecord::charged_bytes),
                        )
                    })
                    .ok_or_else(|| rejected("idempotency charge accounting invalid"))?;
                if bytes > limits.max_bytes.get() {
                    return Err(GatewayError::LimitExceeded(
                        "idempotency byte capacity exhausted".into(),
                    ));
                }
                let records = if let Some(replacement) = replacement {
                    rows.insert(
                        key.as_str(),
                        (as_u64(replacement.charged_bytes())?, replacement.encoded()),
                    )
                    .map_err(storage_error)?;
                    usage.records
                } else {
                    rows.remove(key.as_str()).map_err(storage_error)?;
                    usage
                        .records
                        .checked_sub(1)
                        .ok_or_else(|| rejected("idempotency record accounting invalid"))?
                };
                write_usage(&mut meta, records, bytes)?;
            }
            transaction.commit().map_err(commit_error)
        })
        .await
    }
}

enum Change {
    Complete(TaintedValue),
    Release,
    Retire,
}

#[async_trait]
impl GatewayIdempotencyStore for RedbGatewayIdempotencyStore {
    fn evidence_namespace(&self) -> Result<GatewayEvidenceNamespace, GatewayError> {
        Ok(self.evidence_namespace)
    }

    fn limits(&self) -> GatewayIdempotencyLimits {
        self.limits
    }

    async fn retry_epoch(&self) -> Result<u64, GatewayError> {
        self.run(move |db, _limits| {
            let transaction = db.begin_read().map_err(storage_error)?;
            let meta = transaction.open_table(META).map_err(storage_error)?;
            retry_epoch(&meta)
        })
        .await
    }

    async fn close_retry_epoch(&self, expected: u64) -> Result<u64, GatewayError> {
        self.run(move |db, limits| {
            let transaction = db.begin_write().map_err(storage_error)?;
            let next = expected
                .checked_add(1)
                .ok_or_else(|| rejected("idempotency epoch exhausted"))?;
            {
                let mut meta = transaction.open_table(META).map_err(storage_error)?;
                if retry_epoch(&meta)? != expected {
                    return Err(rejected("idempotency epoch changed before closure"));
                }
                let mut rows = transaction.open_table(RECORDS).map_err(storage_error)?;
                let mut usage = read_usage(&meta, limits)?;
                let mut removed = Vec::new();
                for entry in rows.iter().map_err(storage_error)? {
                    let (key, row) = entry.map_err(storage_error)?;
                    let (charge, encoded) = row.value();
                    let record = decode(key.value(), encoded, charge, limits)?;
                    if record.reclaimable(next)? {
                        usage.records = usage
                            .records
                            .checked_sub(1)
                            .ok_or_else(|| rejected("invalid closure record accounting"))?;
                        usage.bytes = usage
                            .bytes
                            .checked_sub(record.charged_bytes())
                            .ok_or_else(|| rejected("invalid closure byte accounting"))?;
                        removed.push(key.value().to_owned());
                    }
                }
                for key in removed {
                    rows.remove(key.as_str()).map_err(storage_error)?;
                }
                meta.insert("retry_epoch", next).map_err(storage_error)?;
                write_usage(&mut meta, usage.records, usage.bytes)?;
            }
            transaction.commit().map_err(commit_error)?;
            Ok(next)
        })
        .await
    }

    async fn reserve(
        &self,
        key: &str,
        pending: TaintedValue,
    ) -> Result<Option<TaintedValue>, GatewayError> {
        validate_key(key)?;
        let key = key.to_owned();
        self.run(move |db, limits| {
            let identity_epoch = GatewayIdempotencyRecord::retry_epoch(&pending.value)?;
            let pending = GatewayIdempotencyRecord::pending(pending, limits);
            let transaction = db.begin_write().map_err(storage_error)?;
            {
                let mut rows = transaction.open_table(RECORDS).map_err(storage_error)?;
                let mut meta = transaction.open_table(META).map_err(storage_error)?;
                if let Some(row) = rows.get(key.as_str()).map_err(storage_error)? {
                    let (charge, encoded) = row.value();
                    let observed = decode(&key, encoded, charge, limits)?.observe()?;
                    if identity_epoch != GatewayIdempotencyRecord::retry_epoch(&observed.value)? {
                        return Err(rejected("idempotency retry epoch binding mismatch"));
                    }
                    return Ok(Some(observed));
                }
                if identity_epoch != retry_epoch(&meta)? {
                    return Err(rejected("idempotency retry epoch is not open"));
                }
                let record = pending?;
                record.validate_binding(&key)?;
                let usage = read_usage(&meta, limits)?;
                let records = usage
                    .records
                    .checked_add(1)
                    .ok_or_else(|| rejected("idempotency record count overflow"))?;
                let bytes = usage
                    .bytes
                    .checked_add(record.charged_bytes())
                    .ok_or_else(|| rejected("idempotency charge overflow"))?;
                if records > limits.max_records.get() || bytes > limits.max_bytes.get() {
                    return Err(GatewayError::LimitExceeded(
                        "idempotency durable capacity exhausted".into(),
                    ));
                }
                rows.insert(
                    key.as_str(),
                    (as_u64(record.charged_bytes())?, record.encoded()),
                )
                .map_err(storage_error)?;
                write_usage(&mut meta, records, bytes)?;
            }
            transaction.commit().map_err(commit_error)?;
            Ok(None)
        })
        .await
    }

    async fn complete(
        &self,
        key: &str,
        expected: Value,
        result: TaintedValue,
    ) -> Result<(), GatewayError> {
        self.change(key, expected, Change::Complete(result)).await
    }

    async fn release(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        self.change(key, expected, Change::Release).await
    }

    async fn observe(&self, key: &str) -> Result<Option<TaintedValue>, GatewayError> {
        validate_key(key)?;
        let key = key.to_owned();
        self.run(move |db, limits| {
            let transaction = db.begin_read().map_err(storage_error)?;
            let rows = transaction.open_table(RECORDS).map_err(storage_error)?;
            rows.get(key.as_str())
                .map_err(storage_error)?
                .map(|row| {
                    let (charge, encoded) = row.value();
                    decode(&key, encoded, charge, limits)?.observe()
                })
                .transpose()
        })
        .await
    }

    async fn retire(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        self.change(key, expected, Change::Retire).await
    }

    async fn usage(&self) -> Result<GatewayIdempotencyUsage, GatewayError> {
        self.run(move |db, limits| {
            let transaction = db.begin_read().map_err(storage_error)?;
            let meta = transaction.open_table(META).map_err(storage_error)?;
            read_usage(&meta, limits)
        })
        .await
    }
}

fn validate_key(key: &str) -> Result<(), GatewayError> {
    GatewayIdempotencyRecord::validate_key(key)
}

fn retry_epoch(meta: &impl ReadableTable<&'static str, u64>) -> Result<u64, GatewayError> {
    meta.get("retry_epoch")
        .map_err(storage_error)?
        .map(|row| row.value())
        .ok_or_else(|| rejected("idempotency retry barrier missing"))
}

fn require_pending(value: &Value) -> Result<(), GatewayError> {
    if value
        .as_map()
        .and_then(|map| map.get("state"))
        .and_then(Value::as_str)
        != Some("pending")
    {
        return Err(rejected("idempotency record is not pending"));
    }
    Ok(())
}

fn load(
    db: &Database,
    key: &str,
    limits: GatewayIdempotencyLimits,
) -> Result<Option<GatewayIdempotencyRecord>, GatewayError> {
    let transaction = db.begin_read().map_err(storage_error)?;
    let rows = transaction.open_table(RECORDS).map_err(storage_error)?;
    rows.get(key)
        .map_err(storage_error)?
        .map(|row| {
            let (charge, encoded) = row.value();
            decode(key, encoded, charge, limits)
        })
        .transpose()
}

fn decode(
    key: &str,
    encoded: &[u8],
    charge: u64,
    limits: GatewayIdempotencyLimits,
) -> Result<GatewayIdempotencyRecord, GatewayError> {
    if encoded.len() > limits.max_record_bytes.get() {
        return Err(rejected(
            "stored idempotency row exceeds the record byte limit",
        ));
    }
    let charge = usize::try_from(charge)
        .map_err(|_error| rejected("stored idempotency charge exceeds address space"))?;
    let record = GatewayIdempotencyRecord::from_encoded(encoded.to_vec(), charge, limits)?;
    record.validate_binding(key)?;
    Ok(record)
}

fn counter(meta: &impl ReadableTable<&'static str, u64>, key: &str) -> Result<usize, GatewayError> {
    let value = meta
        .get(key)
        .map_err(storage_error)?
        .ok_or_else(|| rejected("idempotency metadata missing"))?
        .value();
    usize::try_from(value).map_err(|_error| rejected("idempotency counter exceeds address space"))
}

fn read_usage(
    meta: &impl ReadableTable<&'static str, u64>,
    limits: GatewayIdempotencyLimits,
) -> Result<GatewayIdempotencyUsage, GatewayError> {
    let records = counter(meta, "records")?;
    let bytes = counter(meta, "bytes")?;
    if records > limits.max_records.get() || bytes > limits.max_bytes.get() {
        return Err(rejected("idempotency counters exceed durable limits"));
    }
    Ok(GatewayIdempotencyUsage { records, bytes })
}

fn write_usage(
    meta: &mut redb::Table<'_, &str, u64>,
    records: usize,
    bytes: usize,
) -> Result<(), GatewayError> {
    meta.insert("records", as_u64(records)?)
        .map_err(storage_error)?;
    meta.insert("bytes", as_u64(bytes)?)
        .map_err(storage_error)?;
    Ok(())
}

fn as_u64(value: usize) -> Result<u64, GatewayError> {
    u64::try_from(value).map_err(|_error| rejected("idempotency counter exceeds storage range"))
}

fn rejected(detail: &str) -> GatewayError {
    GatewayError::Rejected(detail.into())
}

fn conflict(detail: &str) -> GatewayError {
    GatewayError::Indeterminate(detail.into())
}

fn storage_error(error: impl std::fmt::Display) -> GatewayError {
    GatewayError::Rejected(format!(
        "Gateway idempotency storage failed before commit: {error}"
    ))
}

fn commit_error(error: impl std::fmt::Display) -> GatewayError {
    GatewayError::Indeterminate(format!(
        "Gateway idempotency commit outcome unknown: {error}"
    ))
}
