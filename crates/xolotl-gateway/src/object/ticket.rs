//! Upload authorization records, content binding and conditional receipt updates.

use std::collections::BTreeMap;
use xolotl_state::{Backend, StateError};
use xolotl_types::{Path, Value, ValueMap, ValueView};

use super::{
    GATEWAY_COMMITTED_OBJECT_STORE_ID, GatewayPayloadProvenance, IssueObjectUploadTicketRequest,
    collect_large_ref_values,
};
use crate::{
    CompiledSurfaceDescriptor, GatewayError, GatewayLimitProfile, GatewayModality, GatewaySession,
    normalize_optional_string, now_millis, optional_str, push_hex_byte, required_i64, required_str,
    state_path, validate_content_hash, validate_submission_token,
};

const OBJECT_UPLOAD_TICKET_RANDOM_BYTES: usize = 16;

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
    pub(super) committed: bool,
    pub(super) used: bool,
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

    pub(super) fn from_value(value: &Value) -> Result<Self, GatewayError> {
        let map = value
            .as_map()
            .ok_or_else(|| GatewayError::Rejected("upload ticket record must be a map".into()))?;
        let ticket = Self {
            ticket_id: required_str(map, "ticket_id")?.to_string(),
            profile_name: required_str(map, "profile_name")?.to_string(),
            principal_id: required_str(map, "principal_id")?.to_string(),
            surface_id: required_str(map, "surface_id")?.to_string(),
            submission_token: optional_str(map, "submission_token").map(str::to_string),
            modality: parse_modality(required_str(map, "modality")?)?,
            expected_size: optional_u64(map, "expected_size")?,
            expected_digest: optional_str(map, "expected_digest").map(str::to_string),
            allowed_media_types: optional_string_list(map, "allowed_media_types")?,
            expires_at_ms: required_i64(map, "expires_at_ms")?,
            single_use: required_bool(map, "single_use")?,
            committed: required_bool(map, "committed")?,
            used: required_bool(map, "used")?,
        };
        validate_ticket_id(&ticket.ticket_id)?;
        if let Some(digest) = &ticket.expected_digest {
            validate_content_hash(digest)?;
        }
        Ok(ticket)
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
        map.insert("committed".into(), Value::boolean(self.committed));
        map.insert("used".into(), Value::boolean(self.used));
        Ok(Value::map(map))
    }
}

pub(super) struct StoredTicket {
    path: Path,
    value: Value,
    pub(super) ticket: GatewayObjectUploadTicket,
}

impl StoredTicket {
    pub(super) async fn load(state: &Backend, ticket_id: &str) -> Result<Self, GatewayError> {
        let path = upload_ticket_path(ticket_id)?;
        let value = state
            .read(&path)
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

    pub(super) async fn save(self, state: &Backend) -> Result<(), GatewayError> {
        state
            .write_cas(&self.path, Some(self.value), self.ticket.to_value()?)
            .await
            .map(|_commit| ())
            .map_err(|error| match error {
                xolotl_state::StateFailure {
                    error: StateError::CasFailed { .. },
                    ..
                } => GatewayError::Rejected("upload ticket was already consumed".into()),
                other => GatewayError::Rejected(format!("upload ticket update failed: {other}")),
            })
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

pub(super) fn validate_committed_receipt(
    ticket_id: &str,
    ticket: &GatewayObjectUploadTicket,
    value: &Value,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
) -> Result<(), GatewayError> {
    if !ticket.committed || ticket.expected_digest.is_none() || ticket.expected_size.is_none() {
        return Err(GatewayError::Rejected(
            "upload ticket requires a committed content binding".into(),
        ));
    }
    validate_upload_ticket_values(
        ticket_id,
        ticket,
        &[value],
        session,
        surface,
        submission_token,
        now_millis(),
    )
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
    for media_type in &request.allowed_media_types {
        validate_media_type_pattern(media_type)?;
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
    if ticket.used {
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
        for item in collect_large_ref_values(value) {
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
    state_path(&["gateway", "upload-ticket", ticket_id])
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

fn optional_u64(map: &ValueMap, key: &'static str) -> Result<Option<u64>, GatewayError> {
    match map.get(key).map(Value::view) {
        None | Some(ValueView::Null) => Ok(None),
        Some(ValueView::Int(n)) if n >= 0 => Ok(Some(n as u64)),
        _ => Err(GatewayError::Rejected(format!(
            "upload ticket {key} must be a non-negative integer"
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

fn optional_string_list(map: &ValueMap, key: &'static str) -> Result<Vec<String>, GatewayError> {
    match map.get(key).map(Value::view) {
        None | Some(ValueView::Null) => Ok(Vec::new()),
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
