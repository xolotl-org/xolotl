//! Upload authorization records, content binding and conditional receipt updates.

use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroUsize;
use xolotl_kernel::host::HostRuntime;
use xolotl_state::{Backend, StateCursor, StateError};
use xolotl_types::{Path, TaintedValue, Value, ValueMap, ValueView};

use super::{
    GATEWAY_COMMITTED_OBJECT_STORE_ID, GatewayPayloadProvenance, IssueObjectUploadTicketRequest,
    large_ref_values,
};
use crate::{
    CompiledSurfaceDescriptor, GatewayError, GatewayLimitProfile, GatewayModality, GatewaySession,
    normalize_optional_string, push_hex_byte, required_i64, required_str, validate_content_hash,
    validate_internal_hash, validate_submission_token,
};

const OBJECT_UPLOAD_TICKET_RANDOM_BYTES: usize = 16;
const MAX_TICKET_MEDIA_TYPES: usize = 32;
pub(super) const MAX_TICKET_TENSOR_DIMENSIONS: usize = 64;
const MAX_TICKET_INLINE_BYTES: usize = 16 * 1024;
// Includes the State key, provenance envelope and the tagged Value encoding.
// The decoded ticket still has its separate 16 KiB inline-metadata limit.
pub(super) const MAX_TICKET_ENCODED_BYTES: usize = 256 * 1024;
const TICKET_STATE_BUDGET: NonZeroUsize =
    NonZeroUsize::MIN.saturating_add(MAX_TICKET_ENCODED_BYTES - 1);
pub(super) fn ticket_state_budget() -> NonZeroUsize {
    TICKET_STATE_BUDGET
}
#[cfg(test)]
pub(super) const TICKET_MAINTENANCE_BATCH: usize = super::maintenance::BATCH_ENTRIES;
#[cfg(test)]
pub(super) const TICKET_MAINTENANCE_PAGE_BYTES: usize = super::maintenance::PAGE_BYTES;

/// A principal- and surface-bound upload authorization retained by the gateway.
/// Content and proof validation enforce its expiry, optional submission binding,
/// and single-use state before the reference can enter a submitted program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayObjectUploadTicket {
    pub(super) ticket_id: String,
    pub(super) profile_name: String,
    pub(super) principal_id: String,
    pub(super) surface_id: String,
    pub(super) submission_token: Option<String>,
    pub(super) modality: GatewayModality,
    pub(super) expected_size: Option<u64>,
    pub(super) expected_digest: Option<String>,
    pub(super) allowed_media_types: Vec<String>,
    pub(super) expires_at_ms: i64,
    pub(super) single_use: bool,
    pub(super) max_objects: usize,
    pub(super) max_total_bytes: u64,
    pub(super) max_record_bytes: usize,
    pub(super) committed_items: Vec<CommittedObjectBinding>,
    pub(super) used_by: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommittedObjectBinding {
    pub(super) append_ids: Vec<String>,
    pub(super) item: Value,
}

impl CommittedObjectBinding {
    fn to_value(&self) -> Value {
        Value::map(BTreeMap::from([
            (
                "append_ids".into(),
                Value::list(self.append_ids.iter().cloned().map(Value::string).collect()),
            ),
            ("item".into(), self.item.clone()),
        ]))
    }
}

fn committed_items(map: &ValueMap) -> Result<Vec<CommittedObjectBinding>, GatewayError> {
    let Some(ValueView::List(items)) = map.get("committed_items").map(Value::view) else {
        return Err(GatewayError::Rejected(
            "upload ticket committed_items must be a list".into(),
        ));
    };
    if items.len() > 4096 {
        return Err(GatewayError::Rejected(
            "upload ticket has too many committed items".into(),
        ));
    }
    items
        .iter()
        .map(|entry| {
            let fields = entry.as_map().ok_or_else(|| {
                GatewayError::Rejected("upload ticket binding must be a map".into())
            })?;
            let append_ids = required_string_list(fields, "append_ids")?;
            let item = fields.get("item").ok_or_else(|| {
                GatewayError::Rejected("upload ticket binding missing item".into())
            })?;
            if !matches!(
                item.view(),
                ValueView::Blob(_) | ValueView::Tensor(_) | ValueView::Frame(_)
            ) {
                return Err(GatewayError::Rejected(
                    "upload ticket binding item must be a large object reference".into(),
                ));
            }
            Ok(CommittedObjectBinding {
                append_ids,
                item: item.clone(),
            })
        })
        .collect()
}

fn required_ticket_u64(map: &ValueMap, key: &'static str) -> Result<u64, GatewayError> {
    optional_u64(map, key)?
        .ok_or_else(|| GatewayError::Rejected(format!("upload ticket missing {key}")))
}

fn required_ticket_usize(map: &ValueMap, key: &'static str) -> Result<usize, GatewayError> {
    usize::try_from(required_ticket_u64(map, key)?)
        .map_err(|_error| GatewayError::Rejected(format!("upload ticket {key} is out of range")))
}

fn validate_ticket_record_bytes(
    value: &Value,
    ticket_id: &str,
    limit: usize,
) -> Result<(), GatewayError> {
    // Reserve room for the backend provenance envelope and State key. The
    // bounded backend read/write remains the final 256 KiB physical guard.
    let bytes = xolotl_state::host::encoded_size(value)
        .map_err(|error| GatewayError::Rejected(format!("upload ticket encoding failed: {error}")))?
        .checked_add(ticket_id.len() + 4096)
        .ok_or_else(|| GatewayError::Rejected("upload ticket encoded size overflow".into()))?;
    if bytes > limit {
        return Err(GatewayError::Rejected(
            "upload ticket record byte limit exceeded".into(),
        ));
    }
    Ok(())
}

impl GatewayObjectUploadTicket {
    /// Ticket id to pass to `begin_object_upload` or submission provenance.
    pub fn ticket_id(&self) -> &str {
        &self.ticket_id
    }

    /// Server-clock expiry in milliseconds since unix epoch.
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    /// Whether Gateway admission consumes the receipt before execution starts.
    /// A later execution failure does not restore the receipt.
    pub fn is_single_use(&self) -> bool {
        self.single_use
    }

    /// Whether an upload has published the type and backing content authorized
    /// by this receipt.
    pub fn is_committed(&self) -> bool {
        !self.committed_items.is_empty()
    }

    /// Maximum distinct typed object bindings retained by this ticket.
    pub fn max_objects(&self) -> usize {
        self.max_objects
    }

    /// Maximum aggregate canonical backing bytes retained by this ticket.
    pub fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }

    /// Maximum encoded State record bytes accepted by this ticket.
    pub fn max_record_bytes(&self) -> usize {
        self.max_record_bytes
    }

    pub(super) fn from_value(value: &Value) -> Result<Self, GatewayError> {
        validate_ticket_inline_bytes(value)?;
        let map = value
            .as_map()
            .ok_or_else(|| GatewayError::Rejected("upload ticket record must be a map".into()))?;
        let ticket = Self {
            ticket_id: required_str(map, "ticket_id")?.to_string(),
            profile_name: required_str(map, "profile_name")?.to_string(),
            principal_id: required_str(map, "principal_id")?.to_string(),
            surface_id: required_str(map, "surface_id")?.to_string(),
            submission_token: optional_ticket_str(map, "submission_token")?,
            modality: parse_modality(required_str(map, "modality")?)?,
            expected_size: optional_u64(map, "expected_size")?,
            expected_digest: optional_ticket_str(map, "expected_digest")?,
            allowed_media_types: required_string_list(map, "allowed_media_types")?,
            expires_at_ms: required_i64(map, "expires_at_ms")?,
            single_use: required_bool(map, "single_use")?,
            max_objects: required_ticket_usize(map, "max_objects")?,
            max_total_bytes: required_ticket_u64(map, "max_total_bytes")?,
            max_record_bytes: required_ticket_usize(map, "max_record_bytes")?,
            committed_items: committed_items(map)?,
            used_by: optional_ticket_str(map, "used_by")?,
        };
        ticket.validate_record(value)?;
        Ok(ticket)
    }

    fn validate_record(&self, value: &Value) -> Result<(), GatewayError> {
        validate_ticket_inline_bytes(value)?;
        if self.max_objects == 0
            || self.max_objects > 4096
            || self.max_total_bytes == 0
            || self.max_total_bytes > i64::MAX as u64
            || self.max_record_bytes == 0
            || self.max_record_bytes > MAX_TICKET_ENCODED_BYTES
            || self.committed_items.len() > self.max_objects
        {
            return Err(GatewayError::Rejected(
                "upload ticket capacity is invalid".into(),
            ));
        }
        validate_ticket_record_bytes(value, &self.ticket_id, self.max_record_bytes)?;
        validate_ticket_id(&self.ticket_id)?;
        if let Some(digest) = &self.expected_digest {
            validate_content_hash(digest)?;
        }
        if self.used_by.is_some() && self.committed_items.is_empty() {
            return Err(GatewayError::Rejected(
                "upload ticket cannot be used before content is committed".into(),
            ));
        }
        if self.max_objects != 1 && (self.expected_size.is_some() || self.expected_digest.is_some())
        {
            return Err(GatewayError::Rejected(
                "ticket-level content binding requires max_objects = 1".into(),
            ));
        }
        if self.allowed_media_types.len() > MAX_TICKET_MEDIA_TYPES {
            return Err(GatewayError::Rejected(
                "upload ticket has too many media type patterns".into(),
            ));
        }
        for media_type in &self.allowed_media_types {
            validate_media_type_pattern(media_type)?;
        }
        if let Some(token) = self.submission_token.as_deref() {
            validate_submission_token(token)?;
        }
        if let Some(used_by) = self.used_by.as_deref() {
            validate_internal_hash(used_by)?;
        }
        let mut seen_ids = HashSet::new();
        let mut unique_items = HashSet::new();
        let mut unique_blobs = HashSet::new();
        let mut total_bytes = 0_u64;
        for binding in &self.committed_items {
            if binding.append_ids.is_empty() {
                return Err(GatewayError::Rejected(
                    "upload ticket binding has no append identity".into(),
                ));
            }
            for id in &binding.append_ids {
                validate_internal_hash(id)?;
                if !seen_ids.insert(id.as_str()) {
                    return Err(GatewayError::Rejected(
                        "duplicate upload append identity".into(),
                    ));
                }
            }
            let item = &binding.item;
            let blob = item.backing_blob().ok_or_else(|| {
                GatewayError::Rejected("upload ticket committed item has no backing blob".into())
            })?;
            validate_content_hash(&blob.hash)?;
            validate_media_type_pattern_if_present(blob.mime.as_deref())?;
            validate_item_shape(item)?;
            if self
                .expected_digest
                .as_ref()
                .is_some_and(|digest| digest != &blob.hash)
                || self.expected_size.is_some_and(|size| size != blob.size)
            {
                return Err(GatewayError::Rejected(
                    "upload ticket committed item does not match content binding".into(),
                ));
            }
            validate_ticket_values_binding(self, &[item])?;
            if !unique_items.insert(item) {
                return Err(GatewayError::Rejected(
                    "duplicate committed object binding".into(),
                ));
            }
            if unique_blobs.insert(blob) {
                total_bytes = total_bytes.checked_add(blob.size).ok_or_else(|| {
                    GatewayError::Rejected("upload ticket total bytes overflow".into())
                })?;
            }
        }
        if total_bytes > self.max_total_bytes {
            return Err(GatewayError::Rejected(
                "upload ticket total bytes exceeded".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn to_value(&self) -> Result<Value, GatewayError> {
        let mut map = BTreeMap::new();
        map.insert("ticket_id".into(), Value::string(self.ticket_id.clone()));
        map.insert(
            "profile_name".into(),
            Value::string(self.profile_name.clone()),
        );
        map.insert(
            "principal_id".into(),
            Value::string(self.principal_id.clone()),
        );
        map.insert("surface_id".into(), Value::string(self.surface_id.clone()));
        if let Some(submission_token) = &self.submission_token {
            map.insert(
                "submission_token".into(),
                Value::string(submission_token.clone()),
            );
        }
        map.insert(
            "modality".into(),
            Value::string(self.modality.as_str().into()),
        );
        if let Some(size) = self.expected_size {
            let size = i64::try_from(size).map_err(|_error| {
                GatewayError::Rejected("object upload expected_size is out of range".into())
            })?;
            map.insert("expected_size".into(), Value::integer(size));
        }
        if let Some(digest) = &self.expected_digest {
            map.insert("expected_digest".into(), Value::string(digest.clone()));
        }
        map.insert(
            "allowed_media_types".into(),
            Value::list(
                self.allowed_media_types
                    .iter()
                    .cloned()
                    .map(Value::string)
                    .collect(),
            ),
        );
        map.insert("expires_at_ms".into(), Value::integer(self.expires_at_ms));
        map.insert("single_use".into(), Value::boolean(self.single_use));
        map.insert(
            "max_objects".into(),
            Value::integer(i64::try_from(self.max_objects).map_err(|_error| {
                GatewayError::Rejected("upload ticket max_objects is out of range".into())
            })?),
        );
        map.insert(
            "max_total_bytes".into(),
            Value::integer(i64::try_from(self.max_total_bytes).map_err(|_error| {
                GatewayError::Rejected("upload ticket max_total_bytes is out of range".into())
            })?),
        );
        map.insert(
            "max_record_bytes".into(),
            Value::integer(i64::try_from(self.max_record_bytes).map_err(|_error| {
                GatewayError::Rejected("upload ticket max_record_bytes is out of range".into())
            })?),
        );
        map.insert(
            "committed_items".into(),
            Value::list(
                self.committed_items
                    .iter()
                    .map(CommittedObjectBinding::to_value)
                    .collect(),
            ),
        );
        if let Some(used_by) = &self.used_by {
            map.insert("used_by".into(), Value::string(used_by.clone()));
        }
        let value = Value::map(map);
        self.validate_record(&value)?;
        Ok(value)
    }
}

pub(super) struct StoredTicket {
    path: Path,
    value: Value,
    pub(super) ticket: GatewayObjectUploadTicket,
}

/// The two installed ports used by conditional ticket updates. Both are
/// borrowed, so an upload retains no additional Kernel or State owner.
pub(super) struct TicketContext<'a> {
    pub(super) state: &'a Backend,
    pub(super) runtime: &'a HostRuntime,
}

impl StoredTicket {
    pub(super) async fn load(state: &Backend, ticket_id: &str) -> Result<Self, GatewayError> {
        let path = upload_ticket_path(ticket_id)?;
        let value = state
            .read_bounded(&path, ticket_state_budget())
            .await
            .map_err(|error| {
                GatewayError::Rejected(format!("upload ticket lookup failed: {error}"))
            })?
            .ok_or_else(|| GatewayError::Rejected("upload ticket not found".into()))?;
        let ticket = GatewayObjectUploadTicket::from_value(&value)?;
        if ticket.ticket_id != ticket_id {
            return Err(GatewayError::Rejected("upload ticket id mismatch".into()));
        }
        Ok(Self {
            path,
            value,
            ticket,
        })
    }

    pub(super) async fn append(
        mut self,
        context: TicketContext<'_>,
        append_id: &str,
        item: &Value,
        session: &GatewaySession,
        surface: &CompiledSurfaceDescriptor,
        submission_token: Option<&str>,
    ) -> Result<(), GatewayError> {
        let TicketContext { state, runtime } = context;
        for _ in 0..64 {
            if let Some(binding) = self
                .ticket
                .committed_items
                .iter()
                .find(|binding| binding.append_ids.iter().any(|id| id == append_id))
            {
                return if binding.item == *item {
                    Ok(())
                } else {
                    Err(GatewayError::Rejected(
                        "upload append identity changed its binding".into(),
                    ))
                };
            }
            validate_upload_ticket_values(
                &self.ticket.ticket_id,
                &self.ticket,
                &[item],
                session,
                surface,
                submission_token,
                runtime.now_millis(),
            )?;
            if let Some(existing) = self
                .ticket
                .committed_items
                .iter_mut()
                .find(|binding| binding.item == *item)
            {
                existing.append_ids.push(append_id.into());
            } else {
                self.ticket.committed_items.push(CommittedObjectBinding {
                    append_ids: vec![append_id.into()],
                    item: item.clone(),
                });
            }
            let next_value = self.ticket.to_value()?;
            match state
                .write_cas_bounded(
                    &self.path,
                    Some(self.value),
                    next_value,
                    ticket_state_budget(),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(xolotl_state::StateFailure {
                    error: StateError::CasFailed { .. },
                    ..
                }) => {
                    self = Self::load(state, &self.ticket.ticket_id).await?;
                }
                Err(error) => {
                    let read = Self::load(state, &self.ticket.ticket_id).await;
                    if let Ok(current) = read
                        && let Some(binding) = current
                            .ticket
                            .committed_items
                            .iter()
                            .find(|binding| binding.append_ids.iter().any(|id| id == append_id))
                    {
                        return if binding.item == *item {
                            Ok(())
                        } else {
                            Err(GatewayError::Rejected(
                                "upload append identity changed its binding".into(),
                            ))
                        };
                    }
                    return Err(GatewayError::Indeterminate(format!(
                        "upload ticket append: {error}"
                    )));
                }
            }
        }
        Err(GatewayError::Rejected(
            "upload ticket append contention exceeded retry budget".into(),
        ))
    }

    pub(super) async fn consume(
        mut self,
        context: TicketContext<'_>,
        identity: Option<&str>,
        items: &[Value],
        session: &GatewaySession,
        surface: &CompiledSurfaceDescriptor,
        submission_token: Option<&str>,
    ) -> Result<(), GatewayError> {
        let TicketContext { state, runtime } = context;
        if !self.ticket.single_use {
            self = Self::load(state, &self.ticket.ticket_id).await?;
        }
        for _ in 0..64 {
            validate_upload_ticket_scope(
                &self.ticket.ticket_id,
                &self.ticket,
                session,
                surface,
                submission_token,
                runtime.now_millis(),
            )?;
            validate_committed_members(&self.ticket, items.iter())?;
            if !self.ticket.single_use {
                return Ok(());
            }
            let identity = identity.ok_or_else(|| {
                GatewayError::Rejected(
                    "single-use objects require idempotency_key or submission_token".into(),
                )
            })?;
            validate_internal_hash(identity)?;
            self.ticket.used_by = Some(identity.into());
            match state
                .write_cas_bounded(
                    &self.path,
                    Some(self.value),
                    self.ticket.to_value()?,
                    ticket_state_budget(),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(xolotl_state::StateFailure {
                    error: StateError::CasFailed { .. },
                    ..
                }) => {
                    self = Self::load(state, &self.ticket.ticket_id).await?;
                }
                Err(error) => {
                    // A matching read-back proves the marker was written, but it
                    // does not prove an earlier attempt has not executed already.
                    return Err(GatewayError::Indeterminate(format!(
                        "upload ticket consumption: {error}"
                    )));
                }
            }
        }
        Err(GatewayError::Rejected(
            "upload ticket consumption contention exceeded retry budget".into(),
        ))
    }
}

/// One bounded pass over upload tickets. Conditional deletion leaves a
/// concurrent replacement untouched; an uncertain deletion is reported to the
/// caller and the next step restarts at the front.
#[derive(Default)]
pub(crate) struct UploadTicketMaintenance {
    pub(crate) examined: usize,
    pub(crate) removed: usize,
    pub(crate) skipped_oversized: usize,
    pub(crate) next: Option<StateCursor>,
}

pub(super) async fn maintain_upload_tickets_batch(
    state: &Backend,
    cursor: Option<StateCursor>,
    now_ms: i64,
) -> Result<UploadTicketMaintenance, GatewayError> {
    let prefix = crate::paths::gateway_state_path(&["upload-ticket"]).map_err(|error| {
        GatewayError::Rejected(format!("invalid upload ticket prefix: {error}"))
    })?;
    let page =
        super::maintenance::scan_batch(state, prefix, cursor, "upload ticket maintenance").await?;
    let mut result = UploadTicketMaintenance {
        examined: page.examined,
        skipped_oversized: page.skipped_oversized,
        next: page.next,
        ..UploadTicketMaintenance::default()
    };
    for (path, tainted) in page.entries {
        if prune_upload_ticket_entry(state, &path, tainted, now_ms).await? {
            result.removed += 1;
        }
    }
    Ok(result)
}

/// Consume the cursor before I/O so a failed query restarts the next scan at
/// the beginning instead of repeatedly retrying an invalid continuation.
pub(super) async fn maintain_upload_tickets_step(
    state: &Backend,
    cursor: &mut Option<StateCursor>,
    now_ms: i64,
) -> Result<UploadTicketMaintenance, GatewayError> {
    let result = maintain_upload_tickets_batch(state, cursor.take(), now_ms).await;
    if let Ok(batch) = &result {
        *cursor = batch.next.clone();
    }
    result
}

pub(super) async fn prune_upload_ticket_entry(
    state: &Backend,
    path: &Path,
    envelope: TaintedValue,
    now_ms: i64,
) -> Result<bool, GatewayError> {
    let Ok(ticket) = GatewayObjectUploadTicket::from_value(&envelope.value) else {
        return Ok(false);
    };
    if upload_ticket_path(&ticket.ticket_id).ok().as_ref() != Some(path)
        || !(ticket.used_by.is_some() || ticket.expires_at_ms <= now_ms)
    {
        return Ok(false);
    }
    match state
        .write_compare_delete_tainted_bounded(
            path,
            Some(envelope.value),
            envelope.taint,
            ticket_state_budget(),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(xolotl_state::StateFailure {
            error: StateError::CasFailed { .. },
            ..
        }) => Ok(false), // A writer replaced the observed ticket.
        Err(error) => Err(GatewayError::Rejected(format!(
            "upload ticket maintenance delete failed: {error}"
        ))),
    }
}

pub(super) fn provenance_ticket_id(
    provenance: Option<&GatewayPayloadProvenance>,
) -> Result<&str, GatewayError> {
    let Some(provenance) = provenance else {
        return Err(GatewayError::Rejected(
            "large object references require upload ticket or store proof".into(),
        ));
    };
    let proof_id = match provenance.store_proof.as_ref() {
        Some(proof) if proof.store_id == GATEWAY_COMMITTED_OBJECT_STORE_ID => {
            Some(proof.proof.as_str())
        }
        Some(_) => {
            return Err(GatewayError::Rejected(
                "object store proof store_id is not trusted".into(),
            ));
        }
        None => None,
    };
    let ticket_id = match (provenance.upload_ticket.as_deref(), proof_id) {
        (Some(ticket), Some(proof)) if ticket != proof => {
            return Err(GatewayError::Rejected(
                "object provenance names conflicting upload receipts".into(),
            ));
        }
        (Some(ticket), _) => ticket,
        (_, Some(proof)) => proof,
        (None, None) => {
            return Err(GatewayError::Rejected(
                "large object references require upload ticket or store proof".into(),
            ));
        }
    };
    validate_ticket_id(ticket_id)?;
    Ok(ticket_id)
}

pub(super) fn validate_committed_members<'a>(
    ticket: &GatewayObjectUploadTicket,
    items: impl IntoIterator<Item = &'a Value>,
) -> Result<(), GatewayError> {
    let members: HashSet<&Value> = ticket
        .committed_items
        .iter()
        .map(|binding| &binding.item)
        .collect();
    for item in items {
        if !members.contains(item) {
            return Err(GatewayError::Rejected(
                "large object reference is not in the committed ticket".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_ticket_issue_request(
    request: &IssueObjectUploadTicketRequest,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    if request.surface_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "object upload ticket requires a surface_id".into(),
        ));
    }
    if let Some(size) = request.expected_size
        && size > i64::MAX as u64
    {
        return Err(GatewayError::Rejected(
            "object upload expected_size is out of range".into(),
        ));
    }
    if let Some(digest) = normalize_optional_string(request.expected_digest.clone()) {
        validate_content_hash(&digest)?;
    }
    if let Some(token) = normalize_optional_string(request.submission_token.clone()) {
        validate_submission_token(&token)?;
    }
    let ttl = request
        .expires_in_ms
        .map(i64::try_from)
        .transpose()
        .map_err(|_error| {
            GatewayError::Rejected("object upload ticket ttl is out of range".into())
        })?;
    if let Some(ttl) = ttl {
        if ttl <= 0 {
            return Err(GatewayError::Rejected(
                "object upload ticket ttl must be positive".into(),
            ));
        }
        if ttl > limits.max_deadline_ms_from_now {
            return Err(GatewayError::Rejected(
                "object upload ticket ttl exceeds profile deadline window".into(),
            ));
        }
    } else if limits.max_deadline_ms_from_now <= 0 {
        return Err(GatewayError::Rejected(
            "object upload tickets require a positive profile deadline window".into(),
        ));
    }
    if request.allowed_media_types.len() > MAX_TICKET_MEDIA_TYPES {
        return Err(GatewayError::Rejected(
            "object upload ticket has too many media type patterns".into(),
        ));
    }
    for media_type in &request.allowed_media_types {
        validate_media_type_pattern(media_type)?;
    }
    let max_objects = request.max_objects.unwrap_or_else(|| {
        if request.expected_size.is_some() || request.expected_digest.is_some() {
            1
        } else {
            limits.max_ticket_objects
        }
    });
    let max_total_bytes = request
        .max_total_bytes
        .unwrap_or(limits.max_ticket_total_bytes);
    let max_record_bytes = request
        .max_record_bytes
        .unwrap_or(limits.max_ticket_record_bytes);
    if max_objects == 0
        || max_objects > limits.max_ticket_objects
        || max_total_bytes == 0
        || max_total_bytes > limits.max_ticket_total_bytes
        || max_total_bytes > i64::MAX as u64
        || max_record_bytes == 0
        || max_record_bytes > limits.max_ticket_record_bytes
        || max_record_bytes > MAX_TICKET_ENCODED_BYTES
    {
        return Err(GatewayError::Rejected(
            "upload ticket capacity exceeds profile limits".into(),
        ));
    }
    if max_objects != 1 && (request.expected_size.is_some() || request.expected_digest.is_some()) {
        return Err(GatewayError::Rejected(
            "ticket-level content binding requires max_objects = 1".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_media_type_pattern(media_type: &str) -> Result<(), GatewayError> {
    let media_type = media_type.trim();
    if media_type.is_empty()
        || media_type.len() > 128
        || media_type.bytes().any(|b| b.is_ascii_control())
    {
        return Err(GatewayError::Rejected(
            "object upload media type pattern is invalid".into(),
        ));
    }
    let Some((ty, sub)) = media_type.split_once('/') else {
        return Err(GatewayError::Rejected(
            "object upload media type pattern must contain '/'".into(),
        ));
    };
    if ty.is_empty() || sub.is_empty() || ty.contains('*') {
        return Err(GatewayError::Rejected(
            "object upload media type pattern is invalid".into(),
        ));
    }
    if sub.contains('*') && sub != "*" {
        return Err(GatewayError::Rejected(
            "object upload media type wildcard must cover a full subtype".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_upload_ticket_values(
    ticket_id: &str,
    ticket: &GatewayObjectUploadTicket,
    values: &[&Value],
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
    now_ms: i64,
) -> Result<(), GatewayError> {
    validate_upload_ticket_scope(
        ticket_id,
        ticket,
        session,
        surface,
        submission_token,
        now_ms,
    )?;
    validate_ticket_values_binding(ticket, values)
}

pub(super) fn validate_upload_ticket_scope(
    ticket_id: &str,
    ticket: &GatewayObjectUploadTicket,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
    now_ms: i64,
) -> Result<(), GatewayError> {
    if ticket.ticket_id != ticket_id {
        return Err(GatewayError::Rejected("upload ticket id mismatch".into()));
    }
    if ticket.profile_name != session.profile_name {
        return Err(GatewayError::Rejected(
            "upload ticket profile mismatch".into(),
        ));
    }
    if ticket.used_by.is_some() {
        return Err(GatewayError::Rejected("upload ticket already used".into()));
    }
    if ticket.expires_at_ms <= now_ms {
        return Err(GatewayError::Rejected("upload ticket expired".into()));
    }
    if ticket.principal_id != session.principal.principal_id {
        return Err(GatewayError::Rejected(
            "upload ticket principal mismatch".into(),
        ));
    }
    if ticket.surface_id != surface.surface_id {
        return Err(GatewayError::Rejected(
            "upload ticket surface mismatch".into(),
        ));
    }
    if let Some(bound) = ticket.submission_token.as_deref()
        && Some(bound) != submission_token
    {
        return Err(GatewayError::Rejected(
            "upload ticket submission token mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_ticket_values_binding(
    ticket: &GatewayObjectUploadTicket,
    values: &[&Value],
) -> Result<(), GatewayError> {
    let mut found_ref = false;
    for value in values {
        for item in large_ref_values(value) {
            found_ref = true;
            if !modality_allows_value(ticket.modality, item) {
                return Err(GatewayError::Rejected(
                    "upload ticket modality mismatch".into(),
                ));
            }
            let Some(blob) = item.backing_blob() else {
                return Err(GatewayError::Rejected(
                    "upload ticket requires a large object reference".into(),
                ));
            };
            if let Some(size) = ticket.expected_size
                && blob.size != size
            {
                return Err(GatewayError::Rejected("upload ticket size mismatch".into()));
            }
            if let Some(digest) = ticket.expected_digest.as_deref()
                && blob.hash != digest
            {
                return Err(GatewayError::Rejected(
                    "upload ticket digest mismatch".into(),
                ));
            }
            validate_upload_ticket_media_type(ticket, blob.mime.as_deref())?;
        }
    }
    if !found_ref {
        return Err(GatewayError::Rejected(
            "upload ticket requires a large object reference".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_upload_ticket_media_type(
    ticket: &GatewayObjectUploadTicket,
    mime: Option<&str>,
) -> Result<(), GatewayError> {
    if ticket.allowed_media_types.is_empty() {
        return Ok(());
    }
    let mime =
        mime.ok_or_else(|| GatewayError::Rejected("upload ticket requires media type".into()))?;
    if ticket
        .allowed_media_types
        .iter()
        .any(|allowed| media_type_matches(allowed, mime))
    {
        Ok(())
    } else {
        Err(GatewayError::Rejected(
            "upload ticket media type mismatch".into(),
        ))
    }
}

fn modality_allows_value(modality: GatewayModality, value: &Value) -> bool {
    match (modality, value.view()) {
        (GatewayModality::Value, _) => true,
        (GatewayModality::Bytes, ValueView::Blob(_)) => true,
        (GatewayModality::Tensor, ValueView::Tensor(_)) => true,
        (GatewayModality::AudioFrame, ValueView::Frame(frame)) => {
            frame.kind == xolotl_types::FrameKind::Audio
        }
        (GatewayModality::VideoFrame, ValueView::Frame(frame)) => {
            frame.kind == xolotl_types::FrameKind::Video
        }
        (GatewayModality::PoseFrame, ValueView::Frame(frame)) => {
            frame.kind == xolotl_types::FrameKind::Pose
        }
        (GatewayModality::SensorFrame, ValueView::Frame(frame)) => {
            frame.kind == xolotl_types::FrameKind::Sensor
        }
        _ => false,
    }
}

fn media_type_matches(allowed: &str, actual: &str) -> bool {
    allowed == actual
        || allowed == "*/*"
        || allowed.strip_suffix("/*").is_some_and(|prefix| {
            actual.starts_with(prefix) && actual[prefix.len()..].starts_with('/')
        })
}

pub(super) fn upload_ticket_path(ticket_id: &str) -> Result<Path, GatewayError> {
    validate_ticket_id(ticket_id)?;
    crate::paths::gateway_state_path(&["upload-ticket", ticket_id])
        .map_err(|e| GatewayError::Rejected(format!("invalid upload ticket path: {e}")))
}

fn validate_ticket_id(ticket_id: &str) -> Result<(), GatewayError> {
    let ok = !ticket_id.is_empty()
        && ticket_id.len() <= 128
        && ticket_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid upload ticket id".into()))
    }
}

pub(super) fn new_upload_ticket_id() -> Result<String, GatewayError> {
    let mut bytes = [0u8; OBJECT_UPLOAD_TICKET_RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| GatewayError::Rejected(format!("upload ticket entropy failed: {e}")))?;
    let mut id = String::with_capacity(4 + OBJECT_UPLOAD_TICKET_RANDOM_BYTES * 2);
    id.push_str("uot_");
    for byte in bytes {
        push_hex_byte(&mut id, byte);
    }
    Ok(id)
}

pub(super) fn new_append_id() -> Result<String, GatewayError> {
    let mut bytes = [0u8; OBJECT_UPLOAD_TICKET_RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| GatewayError::Rejected(format!("upload append entropy failed: {e}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn optional_u64(map: &ValueMap, key: &'static str) -> Result<Option<u64>, GatewayError> {
    match map.get(key).map(Value::view) {
        None => Ok(None),
        Some(ValueView::Int(n)) if n >= 0 => Ok(Some(n as u64)),
        _ => Err(GatewayError::Rejected(format!(
            "upload ticket {key} must be a non-negative integer"
        ))),
    }
}

fn optional_ticket_str(map: &ValueMap, key: &'static str) -> Result<Option<String>, GatewayError> {
    match map.get(key).map(Value::view) {
        None => Ok(None),
        Some(ValueView::Str(value)) => Ok(Some(value.to_string())),
        Some(_) => Err(GatewayError::Rejected(format!(
            "upload ticket {key} must be a string"
        ))),
    }
}

fn required_bool(map: &ValueMap, key: &'static str) -> Result<bool, GatewayError> {
    match map.get(key).map(Value::view) {
        Some(ValueView::Bool(value)) => Ok(value),
        Some(_) => Err(GatewayError::Rejected(format!(
            "upload ticket {key} must be a bool"
        ))),
        None => Err(GatewayError::Rejected(format!(
            "upload ticket missing {key}"
        ))),
    }
}

fn required_string_list(map: &ValueMap, key: &'static str) -> Result<Vec<String>, GatewayError> {
    match map.get(key).map(Value::view) {
        None => Err(GatewayError::Rejected(format!(
            "upload ticket missing {key}"
        ))),
        Some(ValueView::List(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    GatewayError::Rejected(format!("upload ticket {key} must contain strings"))
                })
            })
            .collect(),
        _ => Err(GatewayError::Rejected(format!(
            "upload ticket {key} must be a list"
        ))),
    }
}

pub(super) fn validate_ticket_inline_bytes(value: &Value) -> Result<(), GatewayError> {
    if crate::value_inspection::inline_bytes(value, MAX_TICKET_INLINE_BYTES).is_none() {
        return Err(GatewayError::Rejected(
            "upload ticket record exceeds inline metadata limit".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_item_shape(item: &Value) -> Result<(), GatewayError> {
    if let ValueView::Tensor(tensor) = item.view()
        && tensor.shape.len() > MAX_TICKET_TENSOR_DIMENSIONS
    {
        return Err(GatewayError::Rejected(
            "upload ticket tensor has too many dimensions".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_media_type_pattern_if_present(
    mime: Option<&str>,
) -> Result<(), GatewayError> {
    if let Some(mime) = mime {
        validate_media_type_pattern(mime)?;
        if mime.contains('*') || mime.trim() != mime {
            return Err(GatewayError::Rejected(
                "committed object media type must be concrete".into(),
            ));
        }
    }
    Ok(())
}

fn parse_modality(value: &str) -> Result<GatewayModality, GatewayError> {
    match value {
        "value" | "VALUE" => Ok(GatewayModality::Value),
        "text" | "TEXT" => Ok(GatewayModality::Text),
        "bytes" | "BYTES" => Ok(GatewayModality::Bytes),
        "tensor" | "TENSOR" => Ok(GatewayModality::Tensor),
        "audio_frame" | "AUDIO_FRAME" => Ok(GatewayModality::AudioFrame),
        "video_frame" | "VIDEO_FRAME" => Ok(GatewayModality::VideoFrame),
        "pose_frame" | "POSE_FRAME" => Ok(GatewayModality::PoseFrame),
        "sensor_frame" | "SENSOR_FRAME" => Ok(GatewayModality::SensorFrame),
        "event" | "EVENT" => Ok(GatewayModality::Event),
        "control" | "CONTROL" => Ok(GatewayModality::Control),
        _ => Err(GatewayError::Rejected(
            "upload ticket modality is invalid".into(),
        )),
    }
}
