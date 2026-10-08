use super::*;
use redb::ReadableTableMetadata;
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    FederationObjectReceiveStore, MAX_OBJECT_GC_FENCES, MAX_OBJECT_RECEIVES, ObjectGcFence,
    ObjectGrantId, ObjectReceivePhase, ObjectReceiveSpec, ObjectReceiveView,
    ObjectReferenceEvidence, ObjectTransferId,
};
use xolotl_types::BlobRef;

const NEXT_RECEIVE_ID_KEY: &str = "object_receive_next_id";
const NEXT_GC_FENCE_ID_KEY: &str = "object_receive_gc_fence_next_id";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveBinding {
    #[serde(with = "fixed_bytes_48")]
    provider: [u8; NODE_ID_LEN],
    subject: StoredFederationSubject,
    grant: u64,
    grant_revision: u64,
    blob: BlobRef,
    #[serde(with = "fixed_bytes_48")]
    owner: [u8; DIGEST_LEN],
}

impl ReceiveBinding {
    fn from_spec(spec: &ObjectReceiveSpec) -> Self {
        Self {
            provider: *spec.provider.as_bytes(),
            subject: StoredFederationSubject::from(&spec.subject),
            grant: spec.grant.get(),
            grant_revision: spec.grant_revision,
            blob: spec.blob.clone(),
            owner: *spec.owner.as_bytes(),
        }
    }

    fn spec(&self) -> Result<ObjectReceiveSpec, FederationError> {
        Ok(ObjectReceiveSpec {
            provider: FederationNodeId::from_bytes(self.provider),
            subject: self.subject.clone().into(),
            grant: ObjectGrantId::new(self.grant).map_err(|_error| FederationError::Corrupt)?,
            grant_revision: self.grant_revision,
            blob: self.blob.clone(),
            owner: Digest::from_bytes(self.owner),
        })
    }

    fn digest(&self) -> Result<[u8; 48], FederationError> {
        let mut hash = Sha384::new();
        hash.update(b"xolotl.federation.object-receive-binding.v1\0");
        hash.update(encode(self)?);
        Ok(hash.finalize().into())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveRow {
    binding: ReceiveBinding,
    phase: u8,
    revision: u64,
}

impl ReceiveRow {
    fn validate(&self, node: FederationNodeId) -> Result<(), FederationError> {
        let valid_phase = matches!((self.phase, self.revision), (1, 1) | (2, 2) | (3, 3));
        if !valid_phase {
            return Err(FederationError::Corrupt);
        }
        self.binding
            .spec()?
            .validate(node)
            .map_err(|_error| FederationError::Corrupt)
    }

    fn view(&self, id: u64, node: FederationNodeId) -> Result<ObjectReceiveView, FederationError> {
        self.validate(node)?;
        let phase = match self.phase {
            1 => ObjectReceivePhase::Pending,
            2 => ObjectReceivePhase::Verified,
            3 => ObjectReceivePhase::Bound,
            _ => return Err(FederationError::Corrupt),
        };
        Ok(ObjectReceiveView {
            transfer: transfer_id(id),
            spec: self.binding.spec()?,
            phase,
            revision: self.revision,
        })
    }
}

fn transfer_id(counter: u64) -> ObjectTransferId {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&counter.to_be_bytes());
    ObjectTransferId::from_bytes(bytes)
}

fn transfer_counter(transfer: ObjectTransferId) -> Result<u64, FederationError> {
    let bytes = transfer.as_bytes();
    if bytes[..8] != [0; 8] {
        return Err(FederationError::Invalid("foreign object transfer ID"));
    }
    let counter = u64::from_be_bytes(
        <[u8; 8]>::try_from(&bytes[8..])
            .map_err(|_error| FederationError::Invalid("invalid object transfer ID"))?,
    );
    if counter == 0 {
        return Err(FederationError::Invalid("invalid object transfer ID"));
    }
    Ok(counter)
}

fn retire_receive(
    store: &RedbFederationStore,
    transfer: ObjectTransferId,
    expected_revision: u64,
    bound: bool,
) -> Result<(), FederationError> {
    let counter = transfer_counter(transfer)?;
    let txn = store.db.begin_write().map_err(storage)?;
    let mut table = txn
        .open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
        .map_err(storage)?;
    let row: ReceiveRow = table
        .get(counter)
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    row.validate(store.node)?;
    if (row.phase == 3) != bound || expected_revision != row.revision {
        return Err(FederationError::Conflict);
    }
    let digest = row.binding.digest()?;
    let mut index = txn
        .open_table(FEDERATION_OBJECT_RECEIVE_INDEX_TABLE)
        .map_err(storage)?;
    if index
        .get(digest.as_slice())
        .map_err(storage)?
        .map(|saved| saved.value())
        != Some(counter)
    {
        return Err(FederationError::Corrupt);
    }
    index.remove(digest.as_slice()).map_err(storage)?;
    table.remove(counter).map_err(storage)?;
    drop(index);
    drop(table);
    txn.commit()
        .map_err(|_error| FederationError::Indeterminate)?;
    Ok(())
}

impl FederationObjectReceiveStore for RedbFederationStore {
    fn bind_receive_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReceiveStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn begin_receive(&self, spec: ObjectReceiveSpec) -> Result<ObjectReceiveView, FederationError> {
        self.decision_peer(spec.provider)?;
        spec.validate(self.node)?;
        let binding = ReceiveBinding::from_spec(&spec);
        let digest = binding.digest()?;
        self.with_decision_write(|txn, _| {
            let fences = txn
                .open_table(FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE)
                .map_err(storage)?;
            if fences
                .get(spec.blob.hash.as_str())
                .map_err(storage)?
                .is_some()
            {
                return Err(FederationError::Conflict);
            }
            drop(fences);
            let mut index = txn
                .open_table(FEDERATION_OBJECT_RECEIVE_INDEX_TABLE)
                .map_err(storage)?;
            if let Some(saved) = index.get(digest.as_slice()).map_err(storage)? {
                let counter = saved.value();
                let receives = txn
                    .open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
                    .map_err(storage)?;
                let row: ReceiveRow = receives
                    .get(counter)
                    .map_err(storage)?
                    .map(|saved| decode(saved.value()))
                    .transpose()?
                    .ok_or(FederationError::Corrupt)?;
                let view = row.view(counter, self.node)?;
                if view.spec != spec {
                    return Err(FederationError::Conflict);
                }
                return Ok(view);
            }
            let mut receives = txn
                .open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
                .map_err(storage)?;
            if receives.len().map_err(storage)? >= MAX_OBJECT_RECEIVES as u64 {
                return Err(FederationError::Capacity);
            }
            let counter = {
                let mut meta = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
                let previous = meta
                    .get(NEXT_RECEIVE_ID_KEY)
                    .map_err(storage)?
                    .map(|saved| {
                        <[u8; 8]>::try_from(saved.value())
                            .map(u64::from_be_bytes)
                            .map_err(|_error| FederationError::Corrupt)
                    })
                    .transpose()?
                    .unwrap_or(0);
                let next = previous.checked_add(1).ok_or(FederationError::Capacity)?;
                meta.insert(NEXT_RECEIVE_ID_KEY, next.to_be_bytes().as_slice())
                    .map_err(storage)?;
                next
            };
            let row = ReceiveRow {
                binding,
                phase: 1,
                revision: 1,
            };
            receives
                .insert(counter, encode(&row)?.as_slice())
                .map_err(storage)?;
            index.insert(digest.as_slice(), counter).map_err(storage)?;
            drop(receives);
            drop(index);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(counter, self.node)
        })
    }

    fn object_receive(
        &self,
        transfer: ObjectTransferId,
    ) -> Result<Option<ObjectReceiveView>, FederationError> {
        let counter = transfer_counter(transfer)?;
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
            .map_err(storage)?;
        table
            .get(counter)
            .map_err(storage)?
            .map(|saved| decode::<ReceiveRow>(saved.value())?.view(counter, self.node))
            .transpose()
    }

    fn mark_object_verified(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
        blob: &BlobRef,
    ) -> Result<ObjectReceiveView, FederationError> {
        let counter = transfer_counter(transfer)?;
        self.with_decision_write(|txn, _| {
            let mut table = txn
                .open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
                .map_err(storage)?;
            let mut row: ReceiveRow = table
                .get(counter)
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            row.validate(self.node)?;
            if row.binding.blob != *blob {
                return Err(FederationError::Conflict);
            }
            if row.phase != 1 {
                if expected_revision == 1 || expected_revision == row.revision {
                    return row.view(counter, self.node);
                }
                return Err(FederationError::Conflict);
            }
            if expected_revision != 1 {
                return Err(FederationError::Conflict);
            }
            row.phase = 2;
            row.revision = 2;
            table
                .insert(counter, encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(counter, self.node)
        })
    }

    fn mark_object_bound(
        &self,
        evidence: ObjectReferenceEvidence,
    ) -> Result<ObjectReceiveView, FederationError> {
        let counter = transfer_counter(evidence.transfer())?;
        self.with_decision_write(|txn, _| {
            let mut table = txn
                .open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
                .map_err(storage)?;
            let mut row: ReceiveRow = table
                .get(counter)
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            row.validate(self.node)?;
            if row.binding.spec()? != *evidence.spec() {
                return Err(FederationError::Conflict);
            }
            if row.phase == 3 {
                if evidence.expected_revision() == 2 || evidence.expected_revision() == 3 {
                    return row.view(counter, self.node);
                }
                return Err(FederationError::Conflict);
            }
            if row.phase != 2 || evidence.expected_revision() != row.revision {
                return Err(FederationError::Conflict);
            }
            row.phase = 3;
            row.revision = 3;
            table
                .insert(counter, encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(counter, self.node)
        })
    }

    fn retire_bound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError> {
        retire_receive(self, transfer, expected_revision, true)
    }

    fn retire_unbound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError> {
        retire_receive(self, transfer, expected_revision, false)
    }

    fn reserve_receive_gc(&self, blob: &BlobRef) -> Result<ObjectGcFence, FederationError> {
        if !BlobRef::is_valid_hash(&blob.hash) {
            return Err(FederationError::Invalid("invalid object hash"));
        }
        self.with_decision_write(|txn, _| {
            let mut fences = txn
                .open_table(FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE)
                .map_err(storage)?;
            if fences.get(blob.hash.as_str()).map_err(storage)?.is_some() {
                return Err(FederationError::Conflict);
            }
            if fences.len().map_err(storage)? >= MAX_OBJECT_GC_FENCES as u64 {
                return Err(FederationError::Capacity);
            }
            let receives = txn
                .open_table(FEDERATION_OBJECT_RECEIVES_TABLE)
                .map_err(storage)?;
            for entry in receives.iter().map_err(storage)? {
                let (_, saved) = entry.map_err(storage)?;
                let row: ReceiveRow = decode(saved.value())?;
                row.validate(self.node)?;
                if row.binding.blob.hash == blob.hash {
                    return Err(FederationError::Conflict);
                }
            }
            drop(receives);
            let generation = {
                let mut meta = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
                let previous = meta
                    .get(NEXT_GC_FENCE_ID_KEY)
                    .map_err(storage)?
                    .map(|saved| {
                        <[u8; 8]>::try_from(saved.value())
                            .map(u64::from_be_bytes)
                            .map_err(|_error| FederationError::Corrupt)
                    })
                    .transpose()?
                    .unwrap_or(0);
                let next = previous.checked_add(1).ok_or(FederationError::Capacity)?;
                meta.insert(NEXT_GC_FENCE_ID_KEY, next.to_be_bytes().as_slice())
                    .map_err(storage)?;
                next
            };
            fences
                .insert(blob.hash.as_str(), generation)
                .map_err(storage)?;
            drop(fences);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(ObjectGcFence {
                hash: blob.hash.clone(),
                generation,
            })
        })
    }

    fn receive_gc_fence(&self, hash: &str) -> Result<Option<ObjectGcFence>, FederationError> {
        if !BlobRef::is_valid_hash(hash) {
            return Err(FederationError::Invalid("invalid object hash"));
        }
        let (txn, _) = self.begin_decision_read()?;
        let fences = txn
            .open_table(FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE)
            .map_err(storage)?;
        fences
            .get(hash)
            .map_err(storage)?
            .map(|saved| {
                let generation = saved.value();
                if generation == 0 {
                    return Err(FederationError::Corrupt);
                }
                Ok(ObjectGcFence {
                    hash: hash.to_owned(),
                    generation,
                })
            })
            .transpose()
    }

    fn active_receive_gc_fences(&self) -> Result<Vec<ObjectGcFence>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let fences = txn
            .open_table(FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE)
            .map_err(storage)?;
        let mut result = Vec::new();
        for entry in fences.iter().map_err(storage)? {
            let (hash, generation) = entry.map_err(storage)?;
            if !BlobRef::is_valid_hash(hash.value()) || generation.value() == 0 {
                return Err(FederationError::Corrupt);
            }
            result.push(ObjectGcFence {
                hash: hash.value().to_owned(),
                generation: generation.value(),
            });
            if result.len() > MAX_OBJECT_GC_FENCES {
                return Err(FederationError::Corrupt);
            }
        }
        Ok(result)
    }

    fn release_receive_gc(&self, fence: &ObjectGcFence) -> Result<(), FederationError> {
        if !BlobRef::is_valid_hash(&fence.hash) || fence.generation == 0 {
            return Err(FederationError::Invalid("invalid object GC fence"));
        }
        self.with_decision_write(|txn, _| {
            let mut fences = txn
                .open_table(FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE)
                .map_err(storage)?;
            let generation = fences
                .get(fence.hash.as_str())
                .map_err(storage)?
                .map(|saved| saved.value())
                .ok_or(FederationError::NotFound)?;
            if generation != fence.generation {
                return Err(FederationError::Conflict);
            }
            fences.remove(fence.hash.as_str()).map_err(storage)?;
            drop(fences);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(())
        })
    }
}
