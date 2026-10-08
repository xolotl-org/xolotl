use std::sync::Arc;

use sha2::{Digest as _, Sha384};

use crate::{Digest, FederationError, FederationNodeId, Position, RequestId, StreamRef};

/// An optional application-level event identity. It need not be revealed to
/// every subscriber, and it is distinct from a stream delivery position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    origin: FederationNodeId,
    namespace: String,
    id: String,
}

impl EventRef {
    /// Name an application event under its origin and namespace.
    pub fn new(
        origin: FederationNodeId,
        namespace: impl Into<String>,
        id: impl Into<String>,
    ) -> Result<Self, FederationError> {
        let namespace = namespace.into();
        let id = id.into();
        validate_literal(&namespace)?;
        validate_literal(&id)?;
        Ok(Self {
            origin,
            namespace,
            id,
        })
    }

    /// Node that assigned this application event identity.
    pub const fn origin(&self) -> FederationNodeId {
        self.origin
    }

    /// Application-defined namespace for the event ID.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Application-defined identifier within the namespace.
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Application or host-defined record type within a published stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventType(String);

impl EventType {
    /// Validate a nonempty, printable event type of at most 256 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, FederationError> {
        let value = value.into();
        validate_literal(&value)?;
        Ok(Self(value))
    }

    /// Literal event type selected by the publishing application.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A semantic schema revision. The application supplies its own stable 32-byte
/// revision and decides whether a received revision is supported.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemaRevision([u8; 32]);

impl SchemaRevision {
    /// Restore an application-assigned semantic schema fingerprint.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Canonical schema revision bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Data needed to construct or losslessly restore an immutable v1 record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordParts {
    /// Ordered stream to which this immutable record belongs.
    pub stream: StreamRef,
    /// Publisher-assigned, one-based position in that stream.
    pub sequence: u64,
    /// Stable request identity used for idempotent publication.
    pub publish_id: RequestId,
    /// Application-defined event classification.
    pub event_type: EventType,
    /// Schema needed to interpret the payload.
    pub schema_revision: SchemaRevision,
    /// Optional application event identity, distinct from stream position.
    pub event_ref: Option<EventRef>,
    /// Opaque application bytes shared without copying across views.
    pub payload: Arc<[u8]>,
}

/// Verified immutable stream record with payload and complete-record digests.
/// Safe construction validates the sequence and binds both digests to the
/// private fields. Shared payload views cannot mutate the record's bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    parts: RecordParts,
    payload_digest: Digest,
    digest: Digest,
}

impl Record {
    /// Construct and hash a new record from complete semantic fields.
    pub fn new(parts: RecordParts) -> Result<Self, FederationError> {
        if parts.sequence == 0 {
            return Err(FederationError::Invalid("record sequence must be positive"));
        }
        let payload_digest = Digest::from_bytes(Sha384::digest(parts.payload.as_ref()).into());
        let digest = record_digest(&parts, payload_digest)?;
        Ok(Self {
            parts,
            payload_digest,
            digest,
        })
    }

    /// Reconstruct a record received over the wire or loaded from storage.
    /// Recompute both digests and reject invalid fields or a different expected
    /// complete-record digest before admitting the immutable record.
    pub fn from_parts(parts: RecordParts, expected: Digest) -> Result<Self, FederationError> {
        let record = Self::new(parts)?;
        if record.digest != expected {
            return Err(FederationError::Conflict);
        }
        Ok(record)
    }

    /// Explicitly recompute both digests for an integrity diagnostic.
    /// Trusted internal transfers rely on the immutable construction invariant;
    /// wire and storage decoders must instead validate with `Self::from_parts`.
    pub fn verify(&self) -> Result<(), FederationError> {
        let recomputed = Self::new(self.parts.clone())?;
        if recomputed.digest != self.digest || recomputed.payload_digest != self.payload_digest {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }

    /// Publisher-owned stream of this record.
    pub const fn stream(&self) -> StreamRef {
        self.parts.stream
    }

    /// One-based stream sequence.
    pub const fn sequence(&self) -> u64 {
        self.parts.sequence
    }

    /// Idempotent publication request identity.
    pub const fn publish_id(&self) -> RequestId {
        self.parts.publish_id
    }

    /// Application event classification.
    pub fn event_type(&self) -> &EventType {
        &self.parts.event_type
    }

    /// Application schema fingerprint.
    pub const fn schema_revision(&self) -> SchemaRevision {
        self.parts.schema_revision
    }

    /// Optional application event identity.
    pub fn event_ref(&self) -> Option<&EventRef> {
        self.parts.event_ref.as_ref()
    }

    /// Borrow opaque payload bytes without allocation.
    pub fn payload(&self) -> &[u8] {
        self.parts.payload.as_ref()
    }

    /// Share payload ownership without copying its bytes.
    pub fn payload_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.parts.payload)
    }

    /// SHA-384 digest of the payload alone.
    pub const fn payload_digest(&self) -> Digest {
        self.payload_digest
    }

    /// SHA-384 digest of all immutable record fields.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Bind this record's sequence to its complete-record digest.
    pub const fn position(&self) -> Position {
        Position::from_valid_record(self.parts.sequence, self.digest)
    }

    /// Return independent fields sharing only immutable payload bytes.
    /// Modifying the returned parts cannot change this verified record.
    pub fn parts(&self) -> RecordParts {
        self.parts.clone()
    }
}

/// One stable publication attempt, deduplicated by stream, retry epoch and ID.
/// A writer captures the epoch before its first append and retains it across
/// every retry, including uncertainty and reopen. It must never obtain a newer
/// epoch to retry an old unknown identity. Epoch closure rejects stale append
/// before any sequence assignment; inspection remains available until explicit
/// exact-receipt retirement. This is business publication, not execution state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishRequest {
    /// Stream to which the publisher will append.
    pub stream: StreamRef,
    /// Nonzero, explicitly selected publisher retry range, fixed across retry.
    pub retry_epoch: u64,
    /// Stable idempotency key retained across retry.
    pub publish_id: RequestId,
    /// Application event classification.
    pub event_type: EventType,
    /// Application schema fingerprint.
    pub schema_revision: SchemaRevision,
    /// Optional event identity separate from the stream position.
    pub event_ref: Option<EventRef>,
    /// Opaque immutable application payload.
    pub payload: Arc<[u8]>,
}

impl PublishRequest {
    /// Bind a returned immutable record to this attempt's fixed retry range.
    pub fn receipt(&self, record: &Record) -> Result<PublicationReceipt, FederationError> {
        if self.retry_epoch == 0 || !self.matches_record(record) {
            return Err(FederationError::Conflict);
        }
        Ok(PublicationReceipt {
            stream: self.stream,
            retry_epoch: self.retry_epoch,
            publish_id: self.publish_id,
            position: record.position(),
        })
    }
    /// Add the publisher-assigned sequence before hashing a committed record.
    pub fn into_parts(self, sequence: u64) -> RecordParts {
        RecordParts {
            stream: self.stream,
            sequence,
            publish_id: self.publish_id,
            event_type: self.event_type,
            schema_revision: self.schema_revision,
            event_ref: self.event_ref,
            payload: self.payload,
        }
    }

    /// Compare this stable request with a previously committed publication.
    pub fn matches_record(&self, record: &Record) -> bool {
        self.stream == record.stream()
            && self.publish_id == record.publish_id()
            && self.event_type == *record.event_type()
            && self.schema_revision == record.schema_revision()
            && self.event_ref.as_ref() == record.event_ref()
            && self.payload.as_ref() == record.payload()
    }
}

/// Owner-confirmed exact append receipt. Unknown attempts have no such release
/// authorization. Retirement returns an identity slot, not a payload slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationReceipt {
    /// Publisher-owned ordered view.
    pub stream: StreamRef,
    /// Original fixed append retry epoch.
    pub retry_epoch: u64,
    /// Original immutable request identity.
    pub publish_id: RequestId,
    /// Exact committed record sequence and digest.
    pub position: Position,
}

/// Maximum exact confirmed identities released in one native transaction.
pub const MAX_PUBLICATION_RETIRE_IDS: usize = 256;

fn validate_literal(value: &str) -> Result<(), FederationError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(FederationError::Invalid("invalid federation literal"));
    }
    Ok(())
}

fn put_bytes(hasher: &mut Sha384, bytes: &[u8]) -> Result<(), FederationError> {
    let len = u64::try_from(bytes.len())
        .map_err(|_error| FederationError::Invalid("record field too large"))?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn record_digest(parts: &RecordParts, payload_digest: Digest) -> Result<Digest, FederationError> {
    let mut hasher = Sha384::new();
    hasher.update(b"xolotl.federation.record.v1\0");
    hasher.update(parts.stream.publisher.as_bytes());
    hasher.update(parts.stream.id.as_bytes());
    hasher.update(parts.sequence.to_be_bytes());
    hasher.update(parts.publish_id.as_bytes());
    put_bytes(&mut hasher, parts.event_type.as_str().as_bytes())?;
    hasher.update(parts.schema_revision.as_bytes());
    match &parts.event_ref {
        Some(reference) => {
            hasher.update([1]);
            hasher.update(reference.origin.as_bytes());
            put_bytes(&mut hasher, reference.namespace.as_bytes())?;
            put_bytes(&mut hasher, reference.id.as_bytes())?;
        }
        None => hasher.update([0]),
    }
    let payload_len = u64::try_from(parts.payload.len())
        .map_err(|_error| FederationError::Invalid("record payload too large"))?;
    hasher.update(payload_len.to_be_bytes());
    hasher.update(payload_digest.as_bytes());
    Ok(Digest::from_bytes(hasher.finalize().into()))
}
