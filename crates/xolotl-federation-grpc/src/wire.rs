//! Strict conversion at the peer wire boundary. No remote identity is inferred
//! from IDs carried inside a frame; the connection supplies that identity.

mod snapshot;

pub(crate) use snapshot::{
    inspect_snapshot, inspect_snapshot_to_pb, read_snapshot, read_snapshot_to_pb, receive_snapshot,
    receive_snapshot_to_pb, snapshot_chunk, snapshot_chunk_to_pb, snapshot_offer,
    snapshot_offer_to_pb, snapshot_received, snapshot_received_to_pb,
};

use std::sync::Arc;

use prost::Message;
use sha2::{Digest as _, Sha384};
use tonic::Status;
use xolotl_federation as domain;
use xolotl_proto::xolotl::v1::federation as pb;
use xolotl_types::BlobRef;

use crate::config::{MAX_FEDERATION_FRAME_BYTES, MAX_FEDERATION_HELLO_BYTES};

/// A finite service group advertised by installed endpoints, not authorization.
/// Protocol v1 binds both peers' bitmaps to their exporter-bound signed Hello
/// transcript. Unknown bits and unsupported protocol versions are rejected.
/// Publication covers subscription/publication operations; Invoke requires a
/// call directory and checked invoker; Object and Snapshot require their readers.
/// Empty advertisements are valid for ordinary outbound-only clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ServedCapability {
    /// Publication and subscription service.
    Publication = 1,
    /// Durable call service with checked execution bridge.
    Invoke = 2,
    /// Exact-object read service.
    Object = 4,
    /// Snapshot offer, read and receipt service.
    Snapshot = 8,
}

pub(crate) fn request_service(body: &pb::sync_frame::Body) -> Option<(u64, ServedCapability)> {
    use pb::sync_frame::Body;
    let (request, capability) = match body {
        Body::Open(value) => (value.request, ServedCapability::Publication),
        Body::Read(value) => (value.request, ServedCapability::Publication),
        Body::Acknowledge(value) => (value.request, ServedCapability::Publication),
        Body::Inspect(value) => (value.request, ServedCapability::Publication),
        Body::Close(value) => (value.request, ServedCapability::Publication),
        Body::RegisterSubject(value) => (value.request, ServedCapability::Publication),
        Body::InspectPublic(value) => (value.request, ServedCapability::Publication),
        Body::ReadPublic(value) => (value.request, ServedCapability::Publication),
        Body::RedeemInvitation(value) => (value.request, ServedCapability::Publication),
        Body::PrepareCall(value) => (value.request, ServedCapability::Invoke),
        Body::InvokeCall(value) => (value.request, ServedCapability::Invoke),
        Body::InspectCall(value) => (value.request, ServedCapability::Invoke),
        Body::CancelCall(value) => (value.request, ServedCapability::Invoke),
        Body::ReadObject(value) => (value.request, ServedCapability::Object),
        Body::InspectSnapshot(value) => (value.request, ServedCapability::Snapshot),
        Body::ReadSnapshot(value) => (value.request, ServedCapability::Snapshot),
        Body::ReceiveSnapshot(value) => (value.request, ServedCapability::Snapshot),
        _ => return None,
    };
    Some((request, capability))
}

pub(crate) fn service_unavailable(request: u64) -> pb::SyncFrame {
    pb::SyncFrame {
        body: Some(pb::sync_frame::Body::Failure(pb::SyncFailure {
            request,
            code: pb::FailureCode::Unavailable as i32,
            message: "federation service is not installed".into(),
            commit_verdict: pb::CommitVerdict::NotCommitted as i32,
        })),
    }
}

pub(crate) struct PeerHello {
    pub served_capabilities: u32,
    pub root: domain::FederationRoot,
    pub authorization: domain::FederationOnlineKeyAuthorization,
    pub root_signature: Vec<u8>,
    pub nonce: [u8; 32],
    pub node: domain::FederationNodeId,
    pub(crate) max_frame_bytes: u64,
    pub(crate) max_in_flight: u32,
    pub(crate) max_batch_records: u32,
    pub(crate) max_batch_bytes: u64,
}

/// Parse an untrusted Hello without turning its node claim into an authenticated
/// peer. The root authorization and exporter-bound proof are checked later.
pub(crate) fn hello(value: pb::Hello) -> Result<PeerHello, Status> {
    let encoded_len = value.encoded_len();
    // Two one-byte tags and two two-byte length prefixes wrap a 3309-byte
    // ML-DSA-65 signature in Authenticate and SyncFrame.
    let auth_frame_len = domain::FederationRoot::SIGNATURE_LEN + 6;
    if encoded_len > MAX_FEDERATION_HELLO_BYTES.saturating_sub(5)
        || value.protocol_version != crate::FEDERATION_PROTOCOL_VERSION
        || value.served_capabilities & !15 != 0
        || !value.required_features.is_empty()
        || value.max_frame_bytes == 0
        || value.max_frame_bytes > MAX_FEDERATION_FRAME_BYTES as u64
        || value.max_in_flight == 0
        || value.max_batch_records == 0
        || value.max_batch_bytes == 0
        || value.max_batch_bytes >= value.max_frame_bytes
        || value.max_frame_bytes < (encoded_len + 5).max(auth_frame_len) as u64
    {
        return Err(Status::invalid_argument("invalid federation Hello"));
    }
    let node = node(value.node_id)?;
    let root = domain::FederationRoot::decode(&value.root_descriptor)
        .map_err(|_error| Status::unauthenticated("invalid federation root"))?;
    if !node.matches_root(&root) {
        return Err(Status::unauthenticated(
            "federation node ID does not match root",
        ));
    }
    let authorization =
        domain::FederationOnlineKeyAuthorization::decode(&value.online_authorization)
            .map_err(|_error| Status::unauthenticated("invalid federation online key"))?;
    if value.root_signature.len() != domain::FederationRoot::SIGNATURE_LEN {
        return Err(Status::unauthenticated(
            "invalid federation root signature length",
        ));
    }
    let nonce = bytes::<32>(value.nonce, "Hello nonce")?;
    if nonce == [0; 32] {
        return Err(Status::invalid_argument("empty federation Hello nonce"));
    }
    Ok(PeerHello {
        served_capabilities: value.served_capabilities,
        root,
        authorization,
        root_signature: value.root_signature,
        nonce,
        node,
        max_frame_bytes: value.max_frame_bytes,
        max_in_flight: value.max_in_flight,
        max_batch_records: value.max_batch_records,
        max_batch_bytes: value.max_batch_bytes,
    })
}

/// Each ordered Hello contributes the complete supported v1 capability set.
/// Future required extensions need a reviewed canonical encoding here.
pub(crate) fn hello_capabilities_digest(initiator: &PeerHello, responder: &PeerHello) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(b"xolotl.federation.hello-capabilities.v1\0");
    for hello in [initiator, responder] {
        hasher.update(crate::FEDERATION_PROTOCOL_VERSION.to_be_bytes());
        hasher.update(hello.served_capabilities.to_be_bytes());
        hasher.update(hello.node.as_bytes());
        hasher.update(hello.max_frame_bytes.to_be_bytes());
        hasher.update(hello.max_in_flight.to_be_bytes());
        hasher.update(hello.max_batch_records.to_be_bytes());
        hasher.update(hello.max_batch_bytes.to_be_bytes());
    }
    hasher.finalize().into()
}

pub(crate) fn authenticate(value: pb::Authenticate) -> Result<Vec<u8>, Status> {
    if value.online_signature.len() != domain::FederationRoot::SIGNATURE_LEN {
        return Err(Status::unauthenticated(
            "invalid federation online signature length",
        ));
    }
    Ok(value.online_signature)
}

pub(crate) fn subject_purpose(value: i32) -> Result<domain::SubjectPurpose, Status> {
    match pb::SubjectPurpose::try_from(value) {
        Ok(pb::SubjectPurpose::Discover) => Ok(domain::SubjectPurpose::Discover),
        Ok(pb::SubjectPurpose::Sync) => Ok(domain::SubjectPurpose::Sync),
        Ok(pb::SubjectPurpose::Invoke) => Ok(domain::SubjectPurpose::Invoke),
        Ok(pb::SubjectPurpose::ObjectRead) => Ok(domain::SubjectPurpose::ObjectRead),
        _ => Err(Status::invalid_argument(
            "invalid federation subject purpose",
        )),
    }
}

/// Hash the exact canonical business message that the publisher will parse.
/// The holder signature is omitted to avoid circular signing. The body kind
/// and length are included, so an equal protobuf payload in another method
/// cannot reuse its signature. The transport must reject duplicate request
/// correlation IDs within a session.
pub(crate) fn subject_request_digest(body: &pb::sync_frame::Body) -> Result<[u8; 48], Status> {
    use pb::sync_frame::Body;
    let (kind, bytes) = match body {
        Body::Open(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (2u8, value.encode_to_vec())
        }
        Body::Read(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (4u8, value.encode_to_vec())
        }
        Body::Acknowledge(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (6u8, value.encode_to_vec())
        }
        Body::Inspect(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (10u8, value.encode_to_vec())
        }
        Body::Close(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (12u8, value.encode_to_vec())
        }
        Body::PrepareCall(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (16u8, value.encode_to_vec())
        }
        Body::InvokeCall(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (18u8, value.encode_to_vec())
        }
        Body::InspectCall(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (20u8, value.encode_to_vec())
        }
        Body::CancelCall(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (22u8, value.encode_to_vec())
        }
        Body::ReadObject(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (28u8, value.encode_to_vec())
        }
        Body::RedeemInvitation(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (30u8, value.encode_to_vec())
        }
        Body::InspectSnapshot(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (32u8, value.encode_to_vec())
        }
        Body::ReadSnapshot(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (34u8, value.encode_to_vec())
        }
        Body::ReceiveSnapshot(value) => {
            let mut value = value.clone();
            value.holder_request_signature.clear();
            (36u8, value.encode_to_vec())
        }
        _ => {
            return Err(Status::invalid_argument(
                "frame has no subject request digest",
            ));
        }
    };
    let mut hasher = Sha384::new();
    hasher.update(b"xolotl.federation.business-frame.v1\0");
    hasher.update([kind]);
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn bytes<const N: usize>(value: Vec<u8>, field: &'static str) -> Result<[u8; N], Status> {
    value
        .try_into()
        .map_err(|_error| Status::invalid_argument(format!("invalid {field} length")))
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, Status> {
    value.ok_or_else(|| Status::invalid_argument(format!("missing {field}")))
}

fn invalid(error: domain::FederationError) -> Status {
    Status::invalid_argument(error.to_string())
}

pub(crate) fn object_blob(value: pb::ObjectBlobRef) -> Result<BlobRef, Status> {
    let hash = BlobRef::sha384_hex(&bytes(value.sha384, "object SHA-384")?);
    if value
        .mime
        .as_ref()
        .is_some_and(|mime| mime.len() > 256 || mime.chars().any(char::is_control))
    {
        return Err(Status::invalid_argument("invalid object MIME"));
    }
    Ok(BlobRef {
        hash,
        size: value.size,
        mime: value.mime,
    })
}

fn object_transfer(value: Vec<u8>) -> Result<domain::ObjectTransferId, Status> {
    let id = bytes::<16>(value, "object transfer ID")?;
    if id == [0; 16] {
        return Err(Status::invalid_argument("zero object transfer ID"));
    }
    Ok(domain::ObjectTransferId::from_bytes(id))
}

pub(crate) fn object_blob_to_pb(value: &BlobRef) -> Result<pb::ObjectBlobRef, Status> {
    if !BlobRef::is_valid_hash(&value.hash) {
        return Err(Status::invalid_argument("invalid object SHA-384"));
    }
    let mut sha384 = Vec::with_capacity(BlobRef::HASH_BYTES);
    for pair in value.hash.as_bytes().as_chunks::<2>().0 {
        let pair = std::str::from_utf8(pair)
            .map_err(|_error| Status::invalid_argument("invalid object SHA-384"))?;
        sha384.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_error| Status::invalid_argument("invalid object SHA-384"))?,
        );
    }
    Ok(pb::ObjectBlobRef {
        sha384,
        size: value.size,
        mime: value.mime.clone(),
    })
}

pub(crate) fn read_object(
    presenter: domain::FederationNodeId,
    subject: domain::FederationSubject,
    value: pb::ReadObject,
) -> Result<domain::ObjectReadRequest, Status> {
    Ok(domain::ObjectReadRequest {
        authenticated_presenter: presenter,
        subject,
        transfer: object_transfer(value.transfer_id)?,
        grant: domain::ObjectGrantId::new(value.grant_id).map_err(invalid)?,
        expected_revision: value.expected_revision,
        blob: object_blob(required(value.blob, "object blob")?)?,
        offset: value.offset,
        max_bytes: value.max_bytes as usize,
    })
}

pub(crate) fn read_object_to_pb(
    request: u64,
    value: &domain::ObjectReadRequest,
) -> Result<pb::ReadObject, Status> {
    Ok(pb::ReadObject {
        request,
        transfer_id: value.transfer.as_bytes().to_vec(),
        grant_id: value.grant.get(),
        expected_revision: value.expected_revision,
        blob: Some(object_blob_to_pb(&value.blob)?),
        offset: value.offset,
        max_bytes: value
            .max_bytes
            .try_into()
            .map_err(|_error| Status::resource_exhausted("object chunk limit overflows"))?,
        context_id: 0,
        holder_request_signature: Vec::new(),
    })
}

pub(crate) fn object_chunk_to_pb(request: u64, value: domain::ObjectReadPage) -> pb::ObjectChunk {
    pb::ObjectChunk {
        request,
        transfer_id: value.transfer.as_bytes().to_vec(),
        grant_id: value.grant.get(),
        revision: value.revision,
        offset: value.offset,
        data: value.bytes,
        end_of_object: value.end_of_object,
        end_of_range: value.end_of_range,
    }
}

pub(crate) fn object_chunk(value: pb::ObjectChunk) -> Result<domain::ObjectReadPage, Status> {
    Ok(domain::ObjectReadPage {
        transfer: object_transfer(value.transfer_id)?,
        grant: domain::ObjectGrantId::new(value.grant_id).map_err(invalid)?,
        revision: value.revision,
        offset: value.offset,
        bytes: value.data,
        end_of_object: value.end_of_object,
        end_of_range: value.end_of_range,
    })
}

pub(crate) fn call_ref(value: pb::CallRef) -> Result<domain::CallRef, Status> {
    domain::CallRef::new(node(value.target)?, bytes(value.id, "call id")?).map_err(invalid)
}

pub(crate) fn call_ref_to_pb(value: domain::CallRef) -> pb::CallRef {
    pb::CallRef {
        target: value.target.as_bytes().to_vec(),
        id: value.id.to_vec(),
    }
}

fn call_status(value: i32) -> Result<domain::CallStatus, Status> {
    match pb::CallStatus::try_from(value) {
        Ok(pb::CallStatus::Reserved) => Ok(domain::CallStatus::Reserved),
        Ok(pb::CallStatus::Preparing) => Ok(domain::CallStatus::Preparing),
        Ok(pb::CallStatus::Accepted) => Ok(domain::CallStatus::Accepted),
        Ok(pb::CallStatus::Finished) => Ok(domain::CallStatus::Finished),
        Ok(pb::CallStatus::Closed) => Ok(domain::CallStatus::Closed),
        Ok(pb::CallStatus::Unproven) => Ok(domain::CallStatus::Unproven),
        _ => Err(Status::invalid_argument("invalid call status")),
    }
}

fn call_status_to_pb(value: domain::CallStatus) -> i32 {
    (match value {
        domain::CallStatus::Reserved => pb::CallStatus::Reserved,
        domain::CallStatus::Preparing => pb::CallStatus::Preparing,
        domain::CallStatus::Accepted => pb::CallStatus::Accepted,
        domain::CallStatus::Finished => pb::CallStatus::Finished,
        domain::CallStatus::Closed => pb::CallStatus::Closed,
        domain::CallStatus::Unproven => pb::CallStatus::Unproven,
    }) as i32
}

pub(crate) fn prepare_call(
    peer: domain::FederationNodeId,
    subject: domain::FederationSubject,
    value: pb::PrepareCall,
) -> Result<domain::PrepareCallRequest, Status> {
    Ok(domain::PrepareCallRequest {
        authenticated_origin: peer,
        subject,
        origin_request_id: domain::RequestId::from_bytes(bytes(
            value.origin_request_id,
            "origin request id",
        )?),
        target: domain::CallTarget {
            export: domain::ExportName::new(value.export_name).map_err(invalid)?,
            path: domain::CallPath::new(value.relative_path).map_err(invalid)?,
            method: domain::CallMethod::new(value.method).map_err(invalid)?,
            contract_digest: bytes(value.contract_digest, "contract digest")?,
        },
        input_digest: domain::Digest::from_bytes(bytes(value.input_digest, "input digest")?),
        input_bytes: value.input_bytes,
        prepare_deadline_ms: value.prepare_deadline_ms,
        execution_deadline_ms: value.execution_deadline_ms,
        result_retention_ms: value.result_retention_ms,
    })
}

pub(crate) fn prepare_call_to_pb(
    request: u64,
    value: &domain::PrepareCallRequest,
) -> pb::PrepareCall {
    pb::PrepareCall {
        request,
        origin_request_id: value.origin_request_id.as_bytes().to_vec(),
        export_name: value.target.export.as_str().to_owned(),
        relative_path: value.target.path.as_str().to_owned(),
        method: value.target.method.as_str().to_owned(),
        contract_digest: value.target.contract_digest.to_vec(),
        input_digest: value.input_digest.as_bytes().to_vec(),
        input_bytes: value.input_bytes,
        prepare_deadline_ms: value.prepare_deadline_ms,
        execution_deadline_ms: value.execution_deadline_ms,
        result_retention_ms: value.result_retention_ms,
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

pub(crate) fn call_prepared(value: pb::CallPrepared) -> Result<domain::CallPrepared, Status> {
    let status = call_status(value.status)?;
    if status == domain::CallStatus::Unproven
        || value.control_revision == 0
        || value.authority_revision == 0
        || value.reserved_until_ms == 0
        || value.execution_deadline_ms < value.reserved_until_ms
        || value.result_retention_ms == 0
    {
        return Err(Status::invalid_argument("invalid CallPrepared receipt"));
    }
    Ok(domain::CallPrepared {
        origin_request_id: domain::RequestId::from_bytes(bytes(
            value.origin_request_id,
            "origin request id",
        )?),
        call: call_ref(required(value.call, "call ref")?)?,
        status,
        reserved_until_ms: value.reserved_until_ms,
        execution_deadline_ms: value.execution_deadline_ms,
        result_retention_ms: value.result_retention_ms,
        authority_revision: value.authority_revision,
        control_revision: value.control_revision,
    })
}

pub(crate) fn call_prepared_to_pb(request: u64, value: &domain::CallPrepared) -> pb::CallPrepared {
    pb::CallPrepared {
        request,
        origin_request_id: value.origin_request_id.as_bytes().to_vec(),
        call: Some(call_ref_to_pb(value.call)),
        status: call_status_to_pb(value.status),
        reserved_until_ms: value.reserved_until_ms,
        execution_deadline_ms: value.execution_deadline_ms,
        result_retention_ms: value.result_retention_ms,
        authority_revision: value.authority_revision,
        control_revision: value.control_revision,
    }
}

pub(crate) fn invoke_call(
    peer: domain::FederationNodeId,
    subject: domain::FederationSubject,
    value: pb::InvokeCall,
) -> Result<domain::InvokeCallRequest, Status> {
    Ok(domain::InvokeCallRequest {
        authenticated_origin: peer,
        subject,
        origin_request_id: domain::RequestId::from_bytes(bytes(
            value.origin_request_id,
            "origin request id",
        )?),
        call: call_ref(required(value.call, "call ref")?)?,
        input: Arc::from(value.input),
    })
}

pub(crate) fn invoke_call_to_pb(request: u64, value: &domain::InvokeCallRequest) -> pb::InvokeCall {
    pb::InvokeCall {
        request,
        origin_request_id: value.origin_request_id.as_bytes().to_vec(),
        call: Some(call_ref_to_pb(value.call)),
        input: value.input.to_vec(),
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

pub(crate) fn call_invoked(value: pb::CallInvoked) -> Result<domain::CallInvoked, Status> {
    let status = call_status(value.status)?;
    if !matches!(
        status,
        domain::CallStatus::Preparing | domain::CallStatus::Accepted | domain::CallStatus::Finished
    ) || value.control_revision == 0
    {
        return Err(Status::invalid_argument("invalid successful Invoke status"));
    }
    Ok(domain::CallInvoked {
        call: call_ref(required(value.call, "call ref")?)?,
        status,
        control_revision: value.control_revision,
    })
}

pub(crate) fn call_invoked_to_pb(request: u64, value: domain::CallInvoked) -> pb::CallInvoked {
    pb::CallInvoked {
        request,
        call: Some(call_ref_to_pb(value.call)),
        status: call_status_to_pb(value.status),
        control_revision: value.control_revision,
    }
}

pub(crate) fn inspect_call(
    peer: domain::FederationNodeId,
    subject: domain::FederationSubject,
    value: pb::InspectCall,
) -> Result<domain::InspectCallRequest, Status> {
    Ok(domain::InspectCallRequest {
        authenticated_origin: peer,
        subject,
        call: call_ref(required(value.call, "call ref")?)?,
    })
}

pub(crate) fn inspect_call_to_pb(
    request: u64,
    value: &domain::InspectCallRequest,
) -> pb::InspectCall {
    pb::InspectCall {
        request,
        call: Some(call_ref_to_pb(value.call)),
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

fn persisted_call_result(
    value: pb::PersistedCallResult,
) -> Result<domain::PersistedCallResult, Status> {
    if value.output.len() > 1024 * 1024 {
        return Err(Status::resource_exhausted(
            "call output exceeds receipt limit",
        ));
    }
    let failure_code = (!value.failure_code.is_empty())
        .then(|| domain::CallFailureCode::new(value.failure_code))
        .transpose()
        .map_err(invalid)?;
    let digest = domain::Digest::from_bytes(bytes(value.output_digest, "call output digest")?);
    let result =
        domain::PersistedCallResult::new(value.succeeded, Arc::from(value.output), failure_code)
            .map_err(invalid)?;
    if result.output_digest != digest {
        return Err(Status::invalid_argument("call output digest mismatch"));
    }
    Ok(result)
}

fn persisted_call_result_to_pb(value: &domain::PersistedCallResult) -> pb::PersistedCallResult {
    pb::PersistedCallResult {
        succeeded: value.succeeded,
        output: value.output.to_vec(),
        output_digest: value.output_digest.as_bytes().to_vec(),
        failure_code: value
            .failure_code
            .as_ref()
            .map_or_else(String::new, |code| code.as_str().to_owned()),
    }
}

pub(crate) fn call_inspected(value: pb::CallInspected) -> Result<domain::CallInspection, Status> {
    if value.unresolved_effect_ids.len() > domain::MAX_CALL_UNRESOLVED_EFFECT_IDS {
        return Err(Status::resource_exhausted(
            "too many unresolved call effects",
        ));
    }
    let status = call_status(value.status)?;
    if value.result.is_some() && status != domain::CallStatus::Finished
        || status != domain::CallStatus::Unproven && value.control_revision == 0
    {
        return Err(Status::invalid_argument(
            "inconsistent CallInspected receipt",
        ));
    }
    Ok(domain::CallInspection {
        call: call_ref(required(value.call, "call ref")?)?,
        status,
        control_revision: value.control_revision,
        authority_revision: value.authority_revision,
        reserved_until_ms: value.reserved_until_ms,
        execution_deadline_ms: value.execution_deadline_ms,
        result_retained_until_ms: value.result_retained_until_ms,
        result: value.result.map(persisted_call_result).transpose()?,
        unresolved_effect_ids: value
            .unresolved_effect_ids
            .into_iter()
            .map(|id| bytes(id, "unresolved effect id"))
            .collect::<Result<Vec<_>, _>>()?,
        cancellation_requested: value.cancellation_requested,
        kernel_cancel_accepted: value.kernel_cancel_accepted,
        execution_stopped: value.execution_stopped,
    })
}

pub(crate) fn call_inspected_to_pb(
    request: u64,
    value: &domain::CallInspection,
) -> pb::CallInspected {
    pb::CallInspected {
        request,
        call: Some(call_ref_to_pb(value.call)),
        status: call_status_to_pb(value.status),
        control_revision: value.control_revision,
        authority_revision: value.authority_revision,
        reserved_until_ms: value.reserved_until_ms,
        execution_deadline_ms: value.execution_deadline_ms,
        result_retained_until_ms: value.result_retained_until_ms,
        result: value.result.as_ref().map(persisted_call_result_to_pb),
        unresolved_effect_ids: value
            .unresolved_effect_ids
            .iter()
            .map(|id| id.to_vec())
            .collect(),
        cancellation_requested: value.cancellation_requested,
        kernel_cancel_accepted: value.kernel_cancel_accepted,
        execution_stopped: value.execution_stopped,
    }
}

pub(crate) fn cancel_call(
    peer: domain::FederationNodeId,
    subject: domain::FederationSubject,
    value: pb::CancelCall,
) -> Result<domain::CancelCallRequest, Status> {
    Ok(domain::CancelCallRequest {
        authenticated_origin: peer,
        subject,
        control_request_id: domain::RequestId::from_bytes(bytes(
            value.control_request_id,
            "control request id",
        )?),
        call: call_ref(required(value.call, "call ref")?)?,
        expected_control_revision: value.expected_control_revision,
    })
}

pub(crate) fn cancel_call_to_pb(request: u64, value: &domain::CancelCallRequest) -> pb::CancelCall {
    pb::CancelCall {
        request,
        control_request_id: value.control_request_id.as_bytes().to_vec(),
        call: Some(call_ref_to_pb(value.call)),
        expected_control_revision: value.expected_control_revision,
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

pub(crate) fn call_cancelled(value: pb::CallCancelled) -> Result<domain::CallCancelled, Status> {
    let status = call_status(value.status)?;
    if !matches!(
        status,
        domain::CallStatus::Preparing
            | domain::CallStatus::Accepted
            | domain::CallStatus::Finished
            | domain::CallStatus::Closed
    ) || value.control_revision == 0
    {
        return Err(Status::invalid_argument("invalid CallCancelled receipt"));
    }
    Ok(domain::CallCancelled {
        control_request_id: domain::RequestId::from_bytes(bytes(
            value.control_request_id,
            "control request id",
        )?),
        call: call_ref(required(value.call, "call ref")?)?,
        status,
        control_revision: value.control_revision,
        cancellation_requested: value.cancellation_requested,
        kernel_cancel_accepted: value.kernel_cancel_accepted,
        execution_stopped: value.execution_stopped,
    })
}

pub(crate) fn call_cancelled_to_pb(
    request: u64,
    value: domain::CallCancelled,
) -> pb::CallCancelled {
    pb::CallCancelled {
        request,
        control_request_id: value.control_request_id.as_bytes().to_vec(),
        call: Some(call_ref_to_pb(value.call)),
        status: call_status_to_pb(value.status),
        control_revision: value.control_revision,
        cancellation_requested: value.cancellation_requested,
        kernel_cancel_accepted: value.kernel_cancel_accepted,
        execution_stopped: value.execution_stopped,
    }
}

pub(crate) fn node(value: Vec<u8>) -> Result<domain::FederationNodeId, Status> {
    Ok(domain::FederationNodeId::from_bytes(bytes::<48>(
        value, "node id",
    )?))
}

pub(crate) fn stream(value: pb::StreamRef) -> Result<domain::StreamRef, Status> {
    Ok(domain::StreamRef {
        publisher: node(value.publisher)?,
        id: domain::StreamId::from_bytes(bytes(value.id, "stream id")?),
    })
}

pub(crate) fn stream_to_pb(value: domain::StreamRef) -> pb::StreamRef {
    pb::StreamRef {
        publisher: value.publisher.as_bytes().to_vec(),
        id: value.id.as_bytes().to_vec(),
    }
}

pub(crate) fn subscription(value: pb::SubscriptionRef) -> Result<domain::SubscriptionRef, Status> {
    Ok(domain::SubscriptionRef {
        subscriber: node(value.subscriber)?,
        id: domain::SubscriptionId::from_bytes(bytes(value.id, "subscription id")?),
    })
}

pub(crate) fn subscription_to_pb(value: domain::SubscriptionRef) -> pb::SubscriptionRef {
    pb::SubscriptionRef {
        subscriber: value.subscriber.as_bytes().to_vec(),
        id: value.id.as_bytes().to_vec(),
    }
}

pub(crate) fn position(value: pb::Position) -> Result<domain::Position, Status> {
    domain::Position::new(
        value.sequence,
        domain::Digest::from_bytes(bytes::<48>(value.digest, "position digest")?),
    )
    .map_err(invalid)
}

pub(crate) fn position_to_pb(value: domain::Position) -> pb::Position {
    pb::Position {
        sequence: value.sequence(),
        digest: value.digest().as_bytes().to_vec(),
    }
}

pub(crate) fn open(
    peer: domain::FederationNodeId,
    value: pb::Open,
) -> Result<domain::OpenRequest, Status> {
    let subscription = subscription(required(value.subscription, "subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "subscription owner is not the peer",
        ));
    }
    let history = match pb::HistoryMode::try_from(value.history_mode) {
        Ok(pb::HistoryMode::All) if value.history_after.is_none() => domain::HistoryStart::All,
        Ok(pb::HistoryMode::After) => domain::HistoryStart::After(position(required(
            value.history_after,
            "history after position",
        )?)?),
        Ok(pb::HistoryMode::FromNow) if value.history_after.is_none() => {
            domain::HistoryStart::FromNow
        }
        _ => return Err(Status::invalid_argument("invalid federation history mode")),
    };
    Ok(domain::OpenRequest {
        authenticated_subscriber: peer,
        request_id: domain::RequestId::from_bytes(bytes(value.request_id, "request id")?),
        subscription,
        stream: stream(required(value.stream, "stream")?)?,
        expected_control_revision: value.expected_control_revision,
        history,
    })
}

pub(crate) fn open_to_pb(request: u64, value: &domain::OpenRequest) -> pb::Open {
    let (history_mode, history_after) = match value.history {
        domain::HistoryStart::All => (pb::HistoryMode::All, None),
        domain::HistoryStart::After(position) => {
            (pb::HistoryMode::After, Some(position_to_pb(position)))
        }
        domain::HistoryStart::FromNow => (pb::HistoryMode::FromNow, None),
    };
    pb::Open {
        request,
        request_id: value.request_id.as_bytes().to_vec(),
        subscription: Some(subscription_to_pb(value.subscription)),
        stream: Some(stream_to_pb(value.stream)),
        expected_control_revision: value.expected_control_revision,
        history_mode: history_mode as i32,
        history_after,
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

pub(crate) fn opened(value: pb::Opened) -> Result<domain::OpenResult, Status> {
    Ok(domain::OpenResult {
        request_id: domain::RequestId::from_bytes(bytes(value.request_id, "request id")?),
        subscription: subscription(required(value.subscription, "subscription")?)?,
        stream: stream(required(value.stream, "stream")?)?,
        export: domain::ExportName::new(value.export_name).map_err(invalid)?,
        publisher_authority: domain::AuthorityRevision {
            peer: value.publisher_peer_revision,
            export: value.publisher_export_revision,
        },
        subscription_revision: value.subscription_revision,
        start: value.start.map(position).transpose()?,
    })
}

pub(crate) fn opened_to_pb(request: u64, value: &domain::OpenResult) -> pb::Opened {
    pb::Opened {
        request,
        request_id: value.request_id.as_bytes().to_vec(),
        subscription: Some(subscription_to_pb(value.subscription)),
        stream: Some(stream_to_pb(value.stream)),
        export_name: value.export.as_str().to_owned(),
        publisher_peer_revision: value.publisher_authority.peer,
        publisher_export_revision: value.publisher_authority.export,
        subscription_revision: value.subscription_revision,
        start: value.start.map(position_to_pb),
    }
}

pub(crate) fn read(
    peer: domain::FederationNodeId,
    value: pb::Read,
) -> Result<domain::ReadRequest, Status> {
    let subscription = subscription(required(value.subscription, "subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "subscription owner is not the peer",
        ));
    }
    Ok(domain::ReadRequest {
        authenticated_subscriber: peer,
        subscription,
        after: value.after.map(position).transpose()?,
        max_records: value.max_records as usize,
        max_bytes: usize::try_from(value.max_bytes)
            .map_err(|_error| Status::invalid_argument("read byte limit overflows usize"))?,
    })
}

pub(crate) fn read_to_pb(request: u64, value: &domain::ReadRequest) -> Result<pb::Read, Status> {
    Ok(pb::Read {
        request,
        subscription: Some(subscription_to_pb(value.subscription)),
        after: value.after.map(position_to_pb),
        max_records: u32::try_from(value.max_records)
            .map_err(|_error| Status::invalid_argument("read record limit overflows u32"))?,
        max_bytes: u64::try_from(value.max_bytes)
            .map_err(|_error| Status::invalid_argument("read byte limit overflows u64"))?,
        context_id: 0,
        holder_request_signature: Vec::new(),
    })
}

pub(crate) fn record(value: pb::Record) -> Result<domain::Record, Status> {
    let event_ref = value
        .event_ref
        .map(|event| {
            domain::EventRef::new(node(event.origin)?, event.namespace, event.id).map_err(invalid)
        })
        .transpose()?;
    let parts = domain::RecordParts {
        stream: stream(required(value.stream, "record stream")?)?,
        sequence: value.sequence,
        publish_id: domain::RequestId::from_bytes(bytes(value.publish_id, "publish id")?),
        event_type: domain::EventType::new(value.event_type).map_err(invalid)?,
        schema_revision: domain::SchemaRevision::from_bytes(bytes(
            value.schema_revision,
            "schema revision",
        )?),
        event_ref,
        payload: Arc::from(value.payload),
    };
    domain::Record::from_parts(
        parts,
        domain::Digest::from_bytes(bytes::<48>(value.digest, "record digest")?),
    )
    .map_err(invalid)
}

pub(crate) fn record_to_pb(value: &domain::Record) -> pb::Record {
    pb::Record {
        stream: Some(stream_to_pb(value.stream())),
        sequence: value.sequence(),
        publish_id: value.publish_id().as_bytes().to_vec(),
        event_type: value.event_type().as_str().to_owned(),
        schema_revision: value.schema_revision().as_bytes().to_vec(),
        event_ref: value.event_ref().map(|event| pb::EventRef {
            origin: event.origin().as_bytes().to_vec(),
            namespace: event.namespace().to_owned(),
            id: event.id().to_owned(),
        }),
        payload: value.payload().to_vec(),
        digest: value.digest().as_bytes().to_vec(),
    }
}

pub(crate) fn batch(
    value: pb::Batch,
) -> Result<(domain::SubscriptionRef, domain::ReadPage), Status> {
    let subscription = subscription(required(value.subscription, "subscription")?)?;
    let records = value
        .records
        .into_iter()
        .map(record)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        subscription,
        domain::ReadPage {
            records,
            head: value.head.map(position).transpose()?,
            minimum_available: value.minimum_available,
        },
    ))
}

pub(crate) fn batch_to_pb(
    request: u64,
    subscription: domain::SubscriptionRef,
    page: &domain::ReadPage,
) -> pb::Batch {
    pb::Batch {
        request,
        subscription: Some(subscription_to_pb(subscription)),
        records: page.records.iter().map(record_to_pb).collect(),
        head: page.head.map(position_to_pb),
        minimum_available: page.minimum_available,
    }
}

pub(crate) fn acknowledge(
    peer: domain::FederationNodeId,
    value: pb::Acknowledge,
) -> Result<domain::AcknowledgeRequest, Status> {
    let subscription = subscription(required(value.subscription, "subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "subscription owner is not the peer",
        ));
    }
    Ok(domain::AcknowledgeRequest {
        authenticated_subscriber: peer,
        subscription,
        position: position(required(value.position, "position")?)?,
    })
}

pub(crate) fn inspect(
    peer: domain::FederationNodeId,
    value: pb::Inspect,
) -> Result<domain::InspectSubscriptionRequest, Status> {
    let subscription = subscription(required(value.subscription, "subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "subscription owner is not the peer",
        ));
    }
    Ok(domain::InspectSubscriptionRequest {
        authenticated_subscriber: peer,
        subscription,
    })
}

pub(crate) fn inspect_to_pb(
    request: u64,
    value: domain::InspectSubscriptionRequest,
) -> pb::Inspect {
    pb::Inspect {
        request,
        subscription: Some(subscription_to_pb(value.subscription)),
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

pub(crate) fn inspected(value: pb::Inspected) -> Result<domain::SubscriptionInspection, Status> {
    let subscription = subscription(required(value.subscription, "subscription")?)?;
    let stream = stream(required(value.stream, "stream")?)?;
    if value.subscription_revision == 0 || value.minimum_available == 0 {
        return Err(Status::invalid_argument(
            "invalid subscription inspection revision or range",
        ));
    }
    Ok(domain::SubscriptionInspection {
        subscription,
        stream,
        export: domain::ExportName::new(value.export_name).map_err(invalid)?,
        subscription_revision: value.subscription_revision,
        start: value.start.map(position).transpose()?,
        acknowledged: value.acknowledged.map(position).transpose()?,
        head: value.head.map(position).transpose()?,
        minimum_available: value.minimum_available,
        closed: value.closed,
    })
}

pub(crate) fn inspected_to_pb(
    request: u64,
    value: &domain::SubscriptionInspection,
) -> pb::Inspected {
    pb::Inspected {
        request,
        subscription: Some(subscription_to_pb(value.subscription)),
        stream: Some(stream_to_pb(value.stream)),
        export_name: value.export.as_str().to_owned(),
        subscription_revision: value.subscription_revision,
        start: value.start.map(position_to_pb),
        acknowledged: value.acknowledged.map(position_to_pb),
        head: value.head.map(position_to_pb),
        minimum_available: value.minimum_available,
        closed: value.closed,
    }
}

pub(crate) fn close(
    peer: domain::FederationNodeId,
    value: pb::Close,
) -> Result<domain::CloseSubscriptionRequest, Status> {
    let subscription = subscription(required(value.subscription, "subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "subscription owner is not the peer",
        ));
    }
    Ok(domain::CloseSubscriptionRequest {
        authenticated_subscriber: peer,
        request_id: domain::RequestId::from_bytes(bytes(value.request_id, "request id")?),
        subscription,
        expected_subscription_revision: value.expected_subscription_revision,
    })
}

pub(crate) fn close_to_pb(request: u64, value: domain::CloseSubscriptionRequest) -> pb::Close {
    pb::Close {
        request,
        request_id: value.request_id.as_bytes().to_vec(),
        subscription: Some(subscription_to_pb(value.subscription)),
        expected_subscription_revision: value.expected_subscription_revision,
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

pub(crate) fn closed(value: pb::Closed) -> Result<domain::CloseSubscriptionResult, Status> {
    if value.subscription_revision == 0 {
        return Err(Status::invalid_argument(
            "invalid closed subscription revision",
        ));
    }
    Ok(domain::CloseSubscriptionResult {
        request_id: domain::RequestId::from_bytes(bytes(value.request_id, "request id")?),
        subscription: subscription(required(value.subscription, "subscription")?)?,
        subscription_revision: value.subscription_revision,
    })
}

pub(crate) fn closed_to_pb(request: u64, value: domain::CloseSubscriptionResult) -> pb::Closed {
    pb::Closed {
        request,
        request_id: value.request_id.as_bytes().to_vec(),
        subscription: Some(subscription_to_pb(value.subscription)),
        subscription_revision: value.subscription_revision,
    }
}

pub(crate) fn failure(request: u64, error: &domain::FederationError) -> pb::SyncFailure {
    use domain::FederationError as E;
    let code = match error {
        E::Invalid(_) => pb::FailureCode::Invalid,
        E::Unauthorized | E::NotFound => pb::FailureCode::Forbidden,
        E::Conflict | E::RevisionConflict | E::Gap { .. } => pb::FailureCode::Conflict,
        E::ResyncRequired { .. } => pb::FailureCode::ResyncRequired,
        E::Capacity => pb::FailureCode::Capacity,
        E::Indeterminate | E::TrustedTimeUnavailable | E::Storage(_) | E::ClockRollback => {
            pb::FailureCode::Unavailable
        }
        E::Corrupt => pb::FailureCode::Internal,
    };
    let message = match error {
        E::Indeterminate | E::TrustedTimeUnavailable | E::Storage(_) | E::ClockRollback => {
            "federation state unavailable".to_owned()
        }
        E::Corrupt => "federation state invalid".to_owned(),
        _ => error.to_string(),
    };
    let commit_verdict = match error {
        E::Indeterminate | E::Storage(_) => pb::CommitVerdict::Indeterminate,
        E::TrustedTimeUnavailable => pb::CommitVerdict::NotCommitted,
        _ => pb::CommitVerdict::Unspecified,
    };
    pb::SyncFailure {
        request,
        code: code as i32,
        message,
        commit_verdict: commit_verdict as i32,
    }
}

pub(crate) fn failure_status(value: pb::SyncFailure) -> Status {
    let code = match pb::FailureCode::try_from(value.code).unwrap_or(pb::FailureCode::Internal) {
        pb::FailureCode::Invalid => tonic::Code::InvalidArgument,
        pb::FailureCode::Forbidden => tonic::Code::PermissionDenied,
        pb::FailureCode::Conflict => tonic::Code::FailedPrecondition,
        pb::FailureCode::ResyncRequired => tonic::Code::OutOfRange,
        pb::FailureCode::Capacity => tonic::Code::ResourceExhausted,
        pb::FailureCode::Unavailable => tonic::Code::Unavailable,
        pb::FailureCode::Unspecified | pb::FailureCode::Internal => tonic::Code::Internal,
    };
    let mut sanitized = value;
    sanitized.message = "remote federation request failed".to_owned();
    Status::with_details(code, &sanitized.message, sanitized.encode_to_vec().into())
}

#[cfg(test)]
mod verdict_tests {
    use super::*;
    use crate::RemoteSyncFailure;
    use anyhow::{Context as _, Result, ensure};

    #[test]
    fn unknown_storage_never_claims_rollback_and_known_time_rejection_does() -> Result<()> {
        for error in [
            domain::FederationError::Storage("private database path".into()),
            domain::FederationError::Indeterminate,
        ] {
            let failure = failure(71, &error);
            ensure!(failure.commit_verdict == pb::CommitVerdict::Indeterminate as i32);
            ensure!(!failure.message.contains("private"));
            let status = failure_status(failure);
            let remote = RemoteSyncFailure::from_status(&status).context("typed remote failure")?;
            ensure!(remote.request == 71);
            ensure!(remote.verdict() == pb::CommitVerdict::Indeterminate);
        }
        ensure!(
            failure(72, &domain::FederationError::TrustedTimeUnavailable).commit_verdict
                == pb::CommitVerdict::NotCommitted as i32
        );
        ensure!(
            failure(73, &domain::FederationError::Unauthorized).commit_verdict
                == pb::CommitVerdict::Unspecified as i32
        );
        ensure!(
            failure(
                74,
                &domain::FederationError::Invalid("result rejected after accepted work")
            )
            .commit_verdict
                == pb::CommitVerdict::Unspecified as i32
        );
        Ok(())
    }

    #[test]
    fn all_remote_verdicts_and_unknown_values_survive_sanitization() -> Result<()> {
        for verdict in [0, 1, 2, 3, 177] {
            let status = failure_status(pb::SyncFailure {
                request: 991,
                code: pb::FailureCode::Conflict as i32,
                message: "remote secret detail".into(),
                commit_verdict: verdict,
            });
            ensure!(status.code() == tonic::Code::FailedPrecondition);
            ensure!(!status.message().contains("secret"));
            let preserved = pb::SyncFailure::decode(status.details())?;
            ensure!(!preserved.message.contains("secret"));
            let remote = RemoteSyncFailure::from_status(&status).context("remote claims")?;
            ensure!(remote.request == 991);
            ensure!(remote.commit_verdict == verdict);
            ensure!(remote.code == pb::FailureCode::Conflict as i32);
            if verdict == 177 {
                ensure!(remote.verdict() == pb::CommitVerdict::Unspecified);
            }
        }
        Ok(())
    }

    #[test]
    fn unspecified_or_absent_remote_verdict_never_implies_rollback() -> Result<()> {
        ensure!(
            RemoteSyncFailure::from_status(&Status::unavailable("transport interrupted")).is_none()
        );
        let unspecified = pb::SyncFailure {
            request: 31,
            code: 6,
            message: String::new(),
            commit_verdict: 0,
        };
        let remote = RemoteSyncFailure::from_status(&failure_status(unspecified))
            .context("unspecified failure")?;
        ensure!(remote.request == 31 && remote.code == 6);
        ensure!(remote.verdict() == pb::CommitVerdict::Unspecified);
        Ok(())
    }
}
