//! Bounded request evidence; [`GatewayIdempotencyStore`] owns retry closure.

use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::sync::OnceLock;
use xolotl_types::{TaintedValue, Value};

use crate::GatewayError;

#[cfg(any(test, feature = "test-support"))]
pub mod tests;

const KEY_BYTES: usize = 64;
const HEADER_BYTES: usize = 12;

/// Identity of one request-evidence ledger, independent of a live Runtime.
///
/// Sharing or reopening the same ledger preserves this identity. Replacing a
/// ledger creates a new identity, even with the same Profile and retry epoch.
/// Clients must retain the original identity and must not relabel an uncertain
/// request after a mismatch. This is a continuity precondition, not authority,
/// execution recovery, or protection against restoring an old database backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GatewayEvidenceNamespace([u8; 32]);

impl GatewayEvidenceNamespace {
    /// Allocate a new ledger identity from operating-system entropy.
    pub fn generate() -> Result<Self, GatewayError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_error| {
            GatewayError::Rejected("request evidence identity entropy is unavailable".into())
        })?;
        Self::from_bytes(bytes)
    }

    /// Validate a retained identity without synthesizing replacement evidence.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, GatewayError> {
        if bytes == [0; 32] {
            return Err(GatewayError::Rejected(
                "request evidence identity is invalid".into(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Canonical bytes used by storage and request-scope fingerprints.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
const FINGERPRINT_FIELDS: [&str; 9] = [
    "schema",
    "effective_key_hash",
    "submission_hash",
    "caller_material_kind",
    "caller_material_hash",
    "profile_name",
    "profile_rev",
    "principal_id",
    "surface_id",
];

/// Fixed capacity of one shared request-evidence owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayIdempotencyLimits {
    /// Pending, completed and retired identities combined.
    pub max_records: NonZeroUsize,
    /// Aggregate encoded rows, keys and outstanding result reservations.
    pub max_bytes: NonZeroUsize,
    /// Maximum encoded row, reserved before any non-idempotent effect.
    pub max_record_bytes: NonZeroUsize,
}

impl Default for GatewayIdempotencyLimits {
    fn default() -> Self {
        Self {
            max_records: NonZeroUsize::MIN.saturating_add(4095),
            max_bytes: NonZeroUsize::MIN.saturating_add(64 * 1024 * 1024 - 1),
            max_record_bytes: NonZeroUsize::MIN.saturating_add(1024 * 1024 - 1),
        }
    }
}

impl GatewayIdempotencyLimits {
    /// Reject a capacity that cannot admit one reserved result.
    pub fn validate(self) -> Result<(), GatewayError> {
        if self.max_record_bytes.get() < HEADER_BYTES
            || self
                .max_record_bytes
                .get()
                .checked_add(KEY_BYTES)
                .is_none_or(|bytes| bytes > self.max_bytes.get())
        {
            return Err(GatewayError::Rejected(
                "invalid idempotency storage capacity".into(),
            ));
        }
        Ok(())
    }
}

/// Logical storage usage, not allocator or process RSS.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayIdempotencyUsage {
    /// Identities retained, including retired fingerprints.
    pub records: usize,
    /// Encoded key/row bytes plus pending result reservations.
    pub bytes: usize,
}

/// One bounded opaque record and its domain-defined charge.
pub struct GatewayIdempotencyRecord {
    encoded: Box<[u8]>,
    charged_bytes: usize,
    metadata: RecordMetadata,
}

struct RecordMetadata {
    key: [u8; KEY_BYTES],
    fingerprint: [u8; 32],
    retry_epoch: u64,
}

impl RecordMetadata {
    fn read(value: &Value) -> Result<Self, GatewayError> {
        state_name(value)?;
        let map = value
            .as_map()
            .ok_or_else(|| GatewayError::Rejected("invalid idempotency fingerprint".into()))?;
        let mut fingerprint = blake3::Hasher::new();
        fingerprint.update(b"xolotl-gateway-record-fingerprint-v1");
        for field in FINGERPRINT_FIELDS {
            let value = map.get(field).and_then(Value::as_str).ok_or_else(|| {
                GatewayError::Rejected("missing idempotency fingerprint field".into())
            })?;
            fingerprint.update(&(value.len() as u64).to_le_bytes());
            fingerprint.update(value.as_bytes());
        }
        let key = map
            .get("effective_key_hash")
            .and_then(Value::as_str)
            .and_then(|key| key.as_bytes().try_into().ok())
            .ok_or_else(|| GatewayError::Rejected("invalid idempotency key fingerprint".into()))?;
        let retry_epoch = GatewayIdempotencyRecord::retry_epoch(value)?;
        fingerprint.update(&retry_epoch.to_le_bytes());
        Ok(Self {
            key,
            fingerprint: *fingerprint.finalize().as_bytes(),
            retry_epoch,
        })
    }
}

impl GatewayIdempotencyRecord {
    /// Read the canonical epoch; an absent field belongs to epoch zero.
    /// A replay probe need not be a valid new row; row encoding separately
    /// validates the complete envelope before admitting a new reservation.
    pub fn retry_epoch(value: &Value) -> Result<u64, GatewayError> {
        match value.as_map().and_then(|map| map.get("retry_epoch")) {
            None => Ok(0),
            Some(value) => value
                .as_str()
                .and_then(|text| {
                    text.parse::<u64>()
                        .ok()
                        .filter(|epoch| epoch.to_string() == text)
                })
                .ok_or_else(|| GatewayError::Rejected("invalid idempotency retry epoch".into())),
        }
    }

    /// Closed-range evidence can release its identity charge only when certain.
    pub fn reclaimable(&self, current: u64) -> Result<bool, GatewayError> {
        if self.metadata.retry_epoch >= current {
            return Ok(false);
        }
        let value = self.observe()?;
        Ok(state_name(&value.value)? == "retired" || Self::require_retirable(&value.value).is_ok())
    }
    /// Validate the stable hashed request key before storage access.
    pub fn validate_key(key: &str) -> Result<(), GatewayError> {
        if key.len() != KEY_BYTES
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GatewayError::Rejected(
                "invalid idempotency storage key".into(),
            ));
        }
        Ok(())
    }

    /// Encode a pending record and reserve its complete result capacity.
    pub fn pending(
        value: TaintedValue,
        limits: GatewayIdempotencyLimits,
    ) -> Result<Self, GatewayError> {
        limits.validate()?;
        require_state(&value.value, "pending")?;
        Self::encode(value, limits, true)
    }

    /// Encode a complete result at its actual bounded size.
    pub fn completed(
        value: TaintedValue,
        limits: GatewayIdempotencyLimits,
    ) -> Result<Self, GatewayError> {
        limits.validate()?;
        require_state(&value.value, "committed")?;
        Self::encode(value, limits, false)
    }

    fn encode(
        value: TaintedValue,
        limits: GatewayIdempotencyLimits,
        reserved: bool,
    ) -> Result<Self, GatewayError> {
        let metadata = RecordMetadata::read(&value.value)?;
        let mut writer = BoundedWriter {
            bytes: vec![0; HEADER_BYTES],
            limit: limits.max_record_bytes.get(),
        };
        writer.bytes[..4].copy_from_slice(b"XGI1");
        serde_json::to_writer(&mut writer, &value.taint).map_err(encoding_error)?;
        let length = u64::try_from(writer.bytes.len() - HEADER_BYTES).map_err(|_error| {
            GatewayError::Rejected("idempotency source length overflow".into())
        })?;
        writer.bytes[4..HEADER_BYTES].copy_from_slice(&length.to_le_bytes());
        serde_json::to_writer(
            &mut writer,
            &xolotl_types::tagged_value::serializable(&value.value),
        )
        .map_err(encoding_error)?;
        let charged_bytes = KEY_BYTES
            .checked_add(if reserved {
                limits.max_record_bytes.get()
            } else {
                writer.bytes.len()
            })
            .ok_or_else(|| {
                GatewayError::LimitExceeded("idempotency byte charge overflow".into())
            })?;
        Ok(Self {
            encoded: writer.bytes.into_boxed_slice(),
            charged_bytes,
            metadata,
        })
    }

    /// Validate a stored bounded envelope and its reservation accounting.
    pub fn from_encoded(
        encoded: Vec<u8>,
        charged_bytes: usize,
        limits: GatewayIdempotencyLimits,
    ) -> Result<Self, GatewayError> {
        limits.validate()?;
        if encoded.len() > limits.max_record_bytes.get() {
            return Err(GatewayError::Rejected(
                "oversized idempotency storage record".into(),
            ));
        }
        let encoded = encoded.into_boxed_slice();
        let value = decode_record(&encoded)?;
        let metadata = RecordMetadata::read(&value.value)?;
        let record = Self {
            encoded,
            charged_bytes,
            metadata,
        };
        let state = state_name(&value.value)?;
        let expected = KEY_BYTES
            .checked_add(match state {
                "pending" => limits.max_record_bytes.get(),
                "committed" | "retired" => record.encoded.len(),
                _ => {
                    return Err(GatewayError::Rejected(
                        "invalid idempotency storage state".into(),
                    ));
                }
            })
            .ok_or_else(|| GatewayError::Rejected("idempotency storage charge overflow".into()))?;
        if expected != charged_bytes {
            return Err(GatewayError::Rejected(
                "invalid idempotency storage charge".into(),
            ));
        }
        Ok(record)
    }

    /// Decode this single bounded row, retaining actual result provenance.
    pub fn observe(&self) -> Result<TaintedValue, GatewayError> {
        decode_record(&self.encoded)
    }

    /// Reject an envelope stored under another request's key.
    pub fn validate_binding(&self, key: &str) -> Result<(), GatewayError> {
        Self::validate_key(key)?;
        if self.metadata.key.as_slice() != key.as_bytes() {
            return Err(GatewayError::Rejected(
                "idempotency record key binding mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Keep the complete request fingerprint unchanged across settlement.
    pub fn validate_replacement(&self, original: &Value) -> Result<(), GatewayError> {
        if self.metadata.fingerprint != RecordMetadata::read(original)?.fingerprint {
            return Err(GatewayError::Rejected(
                "idempotency replacement fingerprint changed".into(),
            ));
        }
        Ok(())
    }

    fn require_retirable(value: &Value) -> Result<(), GatewayError> {
        require_state(value, "committed")?;
        let map = value
            .as_map()
            .ok_or_else(|| GatewayError::Rejected("invalid idempotency result".into()))?;
        let unresolved = map
            .get("unresolved_operations")
            .and_then(Value::as_map)
            .ok_or_else(|| GatewayError::Rejected("missing idempotency effect evidence".into()))?;
        let complete = unresolved
            .get("identities_incomplete")
            .and_then(Value::as_bool)
            == Some(false);
        let empty = unresolved
            .get("operation_ids")
            .and_then(Value::as_list)
            .is_some_and(|ids| ids.is_empty());
        if !complete || !empty {
            return Err(GatewayError::Rejected(
                "unresolved idempotency responsibility cannot retire".into(),
            ));
        }
        match map.get("outcome_status").and_then(Value::as_str) {
            Some("done" | "short") if map.contains_key("outcome_value") => {}
            Some("fail") => {
                let encoded = map
                    .get("failure_json")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        GatewayError::Rejected("missing idempotency failure evidence".into())
                    })?;
                let failure: xolotl_types::Failure =
                    serde_json::from_str(encoded).map_err(decoding_error)?;
                if matches!(failure, xolotl_types::Failure::OutcomeUnknown { .. }) {
                    return Err(GatewayError::Rejected(
                        "unknown idempotency outcome cannot retire".into(),
                    ));
                }
            }
            _ => {
                return Err(GatewayError::Rejected(
                    "missing idempotency outcome evidence".into(),
                ));
            }
        }
        Ok(())
    }

    /// Release only a known complete result, retaining its full replay fingerprint.
    pub fn retired(&self, limits: GatewayIdempotencyLimits) -> Result<Self, GatewayError> {
        let value = self.observe()?;
        Self::require_retirable(&value.value)?;
        let map = value
            .value
            .as_map()
            .ok_or_else(|| GatewayError::Rejected("invalid idempotency result".into()))?;
        let mut retired = BTreeMap::new();
        for key in FINGERPRINT_FIELDS {
            let field = map
                .get(key)
                .ok_or_else(|| GatewayError::Rejected("missing retirement fingerprint".into()))?;
            retired.insert(key.to_owned(), field.clone());
        }
        retired.insert("state".into(), Value::string("retired".into()));
        if let Some(epoch) = map.get("retry_epoch") {
            retired.insert("retry_epoch".into(), epoch.clone());
        }
        Self::encode(
            TaintedValue::new(Value::map(retired), value.taint),
            limits,
            false,
        )
    }

    /// Exact bytes persisted by an adapter; no borrowed Value survives a transaction.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Current row/key charge or the pending reservation.
    pub fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }
}

fn decode_record(encoded: &[u8]) -> Result<TaintedValue, GatewayError> {
    if encoded.get(..4) != Some(b"XGI1".as_slice()) {
        return Err(GatewayError::Rejected(
            "unsupported idempotency storage format".into(),
        ));
    }
    let length = encoded
        .get(4..HEADER_BYTES)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_le_bytes)
        .and_then(|length| usize::try_from(length).ok())
        .and_then(|length| HEADER_BYTES.checked_add(length))
        .filter(|end| *end <= encoded.len())
        .ok_or_else(|| GatewayError::Rejected("invalid idempotency source envelope".into()))?;
    let taint = serde_json::from_slice(&encoded[HEADER_BYTES..length]).map_err(decoding_error)?;
    let mut decoder = serde_json::Deserializer::from_slice(&encoded[length..]);
    let value = xolotl_types::tagged_value::deserialize(&mut decoder).map_err(decoding_error)?;
    decoder.end().map_err(decoding_error)?;
    Ok(TaintedValue::new(value, taint))
}

fn state_name(value: &Value) -> Result<&str, GatewayError> {
    let map = value
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("invalid idempotency record".into()))?;
    if map.get("schema").and_then(Value::as_str) != Some("gateway-idempotency-v1") {
        return Err(GatewayError::Rejected(
            "unsupported idempotency record schema".into(),
        ));
    }
    for key in [
        "effective_key_hash",
        "submission_hash",
        "caller_material_hash",
    ] {
        GatewayIdempotencyRecord::validate_key(
            map.get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| GatewayError::Rejected("missing idempotency fingerprint".into()))?,
        )?;
    }
    for key in ["profile_name", "profile_rev", "principal_id", "surface_id"] {
        if map
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(GatewayError::Rejected(
                "missing idempotency request scope".into(),
            ));
        }
    }
    if !matches!(
        map.get("caller_material_kind").and_then(Value::as_str),
        Some("idempotency_key" | "submission_token")
    ) {
        return Err(GatewayError::Rejected(
            "invalid idempotency material kind".into(),
        ));
    }
    map.get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::Rejected("missing idempotency record state".into()))
}

fn require_state(value: &Value, required: &str) -> Result<(), GatewayError> {
    if state_name(value)? != required {
        return Err(GatewayError::Rejected(
            "idempotency record is not in the required state".into(),
        ));
    }
    Ok(())
}

fn encoding_error(error: serde_json::Error) -> GatewayError {
    GatewayError::LimitExceeded(format!("idempotency record encoding failed: {error}"))
}

fn decoding_error(error: impl std::fmt::Display) -> GatewayError {
    GatewayError::Rejected(format!("invalid idempotency storage record: {error}"))
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("idempotency record capacity exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One atomic domain for request records and cumulative capacity.
///
/// Retained acceptance preserves the complete positive [`crate::GatewayProfileRev`]
/// range. The `accepted_profile_rev` field's integer/string representation and
/// strict validation are defined by [`crate::GatewayAccepted::profile_rev`];
/// storage must preserve that representation without numeric coercion.
///
/// A trusted host explicitly closes the store-wide retry epoch when clients
/// have finished that retry range. Closure is not a TTL or a profile reload:
/// reserve atomically rejects new reservations outside the current epoch before
/// any effect, even if their detail has been reclaimed. Existing closed-range
/// evidence remains queryable through reserve/replay, never redispatched.
/// SubmitOptions.retry_epoch defaults to zero, independently of the literal
/// key/token field. No key/token string prefix has special meaning. Relabelling an
/// old request into a new epoch is a new request, not a retry. Clients must not
/// automatically move an uncertain request to a newer epoch. The epoch never
/// resets or wraps and is independent of profile revision and caller authority.
///
/// Closure retains pending and uncertain evidence and their capacity charges.
/// It reclaims only closed-range retired fingerprints or complete results with
/// no unresolved responsibility. Already reserved owners may still settle;
/// later closure can reclaim their known results. If unresolved entries alone
/// fill capacity, closure cannot restore admission; the host must reconcile.
/// No execution is persisted. Memory storage loses the barrier on owner loss
/// and is not restart-safe; its replacement namespace makes guarded old requests
/// reject rather than silently acquiring new evidence. Durable storage commits
/// barrier and reclamation together. The fixed u64 barrier and 32-byte namespace
/// are owner metadata, not charged records;
/// closure scans at most max_records rows with one decoded row plus bounded
/// key scratch, never accumulating result payloads.
#[async_trait]
pub trait GatewayIdempotencyStore: Send + Sync {
    /// Stable ledger identity. Failure prevents discovery or guarded submission;
    /// it must not be treated as an empty store or a new identity.
    fn evidence_namespace(&self) -> Result<GatewayEvidenceNamespace, GatewayError>;
    /// Fixed limits shared by clones and persistent reopen.
    fn limits(&self) -> GatewayIdempotencyLimits;
    /// Current store-wide retry epoch, independent of profile revisions.
    async fn retry_epoch(&self) -> Result<u64, GatewayError>;
    /// Trusted-host compare-and-close of the current retry range. Atomically
    /// advance its permanent barrier and reclaim only certain closed evidence.
    /// Pending/unknown entries remain observable and settleable, never evicted.
    /// Mismatched expectations and exhausted u64 reject without changing state.
    /// A failed durable commit is indeterminate: read the epoch before retrying.
    async fn close_retry_epoch(&self, expected: u64) -> Result<u64, GatewayError>;
    /// Observe an existing identity in its original epoch, even if closed or
    /// capacity is full; otherwise reserve a new pending result only in the
    /// open epoch. A replay cannot redispatch a pending/committed/retired row.
    async fn reserve(
        &self,
        key: &str,
        pending: TaintedValue,
    ) -> Result<Option<TaintedValue>, GatewayError>;
    /// Compare the original pending value and settle its reserved result bytes.
    async fn complete(
        &self,
        key: &str,
        expected: Value,
        result: TaintedValue,
    ) -> Result<(), GatewayError>;
    /// Remove only the original pending reservation after known pre-effect failure.
    async fn release(&self, key: &str, expected: Value) -> Result<(), GatewayError>;
    /// Observe exactly one retained identity, without scanning or mutating it.
    async fn observe(&self, key: &str) -> Result<Option<TaintedValue>, GatewayError>;
    /// Explicitly consume a known result into a permanent fingerprint tombstone.
    async fn retire(&self, key: &str, expected: Value) -> Result<(), GatewayError>;
    /// Read incremental logical accounting.
    async fn usage(&self) -> Result<GatewayIdempotencyUsage, GatewayError>;
}

/// An explicitly selected bounded, nonpersistent request store.
#[derive(Default)]
pub struct MemoryGatewayIdempotencyStore {
    limits: GatewayIdempotencyLimits,
    evidence_namespace: OnceLock<GatewayEvidenceNamespace>,
    state: Mutex<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    records: BTreeMap<String, GatewayIdempotencyRecord>,
    usage: GatewayIdempotencyUsage,
    retry_epoch: u64,
}

impl MemoryGatewayIdempotencyStore {
    /// Construct one shared owner with explicit logical limits.
    pub fn new(limits: GatewayIdempotencyLimits) -> Result<Self, GatewayError> {
        limits.validate()?;
        Ok(Self {
            limits,
            evidence_namespace: OnceLock::new(),
            state: Mutex::default(),
        })
    }

    fn replace(
        &self,
        key: &str,
        expected: Value,
        replacement: impl FnOnce(
            &GatewayIdempotencyRecord,
            TaintedValue,
        ) -> Result<GatewayIdempotencyRecord, GatewayError>,
    ) -> Result<(), GatewayError> {
        GatewayIdempotencyRecord::validate_key(key)?;
        let mut state = self.state.lock();
        let current = state.records.get(key).ok_or_else(|| {
            GatewayError::Indeterminate("idempotency record missing during settlement".into())
        })?;
        let observed = current.observe()?;
        if observed.value != expected {
            return Err(GatewayError::Indeterminate(
                "idempotency record changed during settlement".into(),
            ));
        }
        let replacement = replacement(current, observed)?;
        replacement.validate_binding(key)?;
        replacement.validate_replacement(&expected)?;
        let bytes = state
            .usage
            .bytes
            .checked_sub(current.charged_bytes())
            .and_then(|bytes| bytes.checked_add(replacement.charged_bytes()))
            .filter(|bytes| *bytes <= self.limits.max_bytes.get())
            .ok_or_else(|| {
                GatewayError::Indeterminate("idempotency storage accounting invalid".into())
            })?;
        let old = state.records.insert(key.into(), replacement);
        state.usage.bytes = bytes;
        drop(state);
        drop(old);
        Ok(())
    }
}

#[async_trait]
impl GatewayIdempotencyStore for MemoryGatewayIdempotencyStore {
    fn evidence_namespace(&self) -> Result<GatewayEvidenceNamespace, GatewayError> {
        if let Some(namespace) = self.evidence_namespace.get() {
            return Ok(*namespace);
        }
        let namespace = GatewayEvidenceNamespace::generate()?;
        let _installed = self.evidence_namespace.set(namespace);
        self.evidence_namespace.get().copied().ok_or_else(|| {
            GatewayError::Rejected("request evidence identity could not initialize".into())
        })
    }
    fn limits(&self) -> GatewayIdempotencyLimits {
        self.limits
    }

    async fn retry_epoch(&self) -> Result<u64, GatewayError> {
        Ok(self.state.lock().retry_epoch)
    }

    async fn close_retry_epoch(&self, expected: u64) -> Result<u64, GatewayError> {
        let mut state = self.state.lock();
        if state.retry_epoch != expected {
            return Err(GatewayError::Rejected(
                "idempotency epoch changed before closure".into(),
            ));
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| GatewayError::Rejected("idempotency epoch exhausted".into()))?;
        let mut removed = Vec::new();
        for (key, record) in &state.records {
            if record.reclaimable(next)? {
                removed.push(key.clone());
            }
        }
        state.retry_epoch = next;
        for key in removed {
            if let Some(record) = state.records.remove(&key) {
                state.usage.records -= 1;
                state.usage.bytes -= record.charged_bytes();
            }
        }
        Ok(next)
    }

    async fn reserve(
        &self,
        key: &str,
        pending: TaintedValue,
    ) -> Result<Option<TaintedValue>, GatewayError> {
        GatewayIdempotencyRecord::validate_key(key)?;
        let identity_epoch = GatewayIdempotencyRecord::retry_epoch(&pending.value)?;
        let pending = GatewayIdempotencyRecord::pending(pending, self.limits).and_then(|record| {
            record.validate_binding(key)?;
            Ok(record)
        });
        let mut state = self.state.lock();
        if let Some(current) = state.records.get(key) {
            if identity_epoch != current.metadata.retry_epoch {
                return Err(GatewayError::Rejected(
                    "idempotency retry epoch binding mismatch".into(),
                ));
            }
            return current.observe().map(Some);
        }
        if identity_epoch != state.retry_epoch {
            return Err(GatewayError::Rejected(
                "idempotency retry epoch is not open".into(),
            ));
        }
        let pending = pending?;
        let bytes = state
            .usage
            .bytes
            .checked_add(pending.charged_bytes())
            .filter(|bytes| *bytes <= self.limits.max_bytes.get());
        if state.usage.records >= self.limits.max_records.get() || bytes.is_none() {
            return Err(GatewayError::LimitExceeded(
                "idempotency storage capacity exhausted".into(),
            ));
        }
        state.usage.bytes = bytes.ok_or_else(|| {
            GatewayError::LimitExceeded("idempotency byte capacity exhausted".into())
        })?;
        state.usage.records += 1;
        state.records.insert(key.into(), pending);
        Ok(None)
    }

    async fn complete(
        &self,
        key: &str,
        expected: Value,
        mut result: TaintedValue,
    ) -> Result<(), GatewayError> {
        self.replace(key, expected, |_current, observed| {
            require_state(&observed.value, "pending")?;
            result.taint.union(&observed.taint);
            GatewayIdempotencyRecord::completed(result, self.limits)
        })
    }

    async fn release(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        GatewayIdempotencyRecord::validate_key(key)?;
        let mut state = self.state.lock();
        let Some(current) = state.records.get(key) else {
            return Err(GatewayError::Indeterminate(
                "idempotency reservation missing during release".into(),
            ));
        };
        let observed = current.observe()?;
        if observed.value != expected {
            return Err(GatewayError::Indeterminate(
                "idempotency reservation changed before release".into(),
            ));
        }
        require_state(&observed.value, "pending")?;
        let bytes = state
            .usage
            .bytes
            .checked_sub(current.charged_bytes())
            .ok_or_else(|| {
                GatewayError::Indeterminate("invalid idempotency release accounting".into())
            })?;
        let old = state.records.remove(key);
        state.usage.records -= 1;
        state.usage.bytes = bytes;
        drop(state);
        drop(old);
        Ok(())
    }

    async fn observe(&self, key: &str) -> Result<Option<TaintedValue>, GatewayError> {
        GatewayIdempotencyRecord::validate_key(key)?;
        self.state
            .lock()
            .records
            .get(key)
            .map(GatewayIdempotencyRecord::observe)
            .transpose()
    }

    async fn retire(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        self.replace(key, expected, |current, _observed| {
            current.retired(self.limits)
        })
    }

    async fn usage(&self) -> Result<GatewayIdempotencyUsage, GatewayError> {
        Ok(self.state.lock().usage)
    }
}
