use super::*;
use crate::{
    FederationObjectReceiveStore, MAX_OBJECT_GC_FENCES, MAX_OBJECT_RECEIVES, ObjectGcFence,
    ObjectReceivePhase, ObjectReceiveSpec, ObjectReceiveView, ObjectReferenceEvidence,
    ObjectTransferId,
};
use xolotl_types::BlobRef;

fn transfer_id(counter: u64) -> ObjectTransferId {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&counter.to_be_bytes());
    ObjectTransferId::from_bytes(bytes)
}

impl FederationObjectReceiveStore for MemoryFederationStore {
    fn bind_receive_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReceiveStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.local_node
    }

    fn begin_receive(&self, spec: ObjectReceiveSpec) -> Result<ObjectReceiveView, FederationError> {
        self.decision_peer(spec.provider)?;
        spec.validate(self.local_node)?;
        let mut state = self.lock()?;
        if state.object_gc_fences.contains_key(&spec.blob.hash) {
            return Err(FederationError::Conflict);
        }
        if let Some(view) = state
            .object_receives
            .values()
            .find(|view| view.spec == spec)
        {
            return Ok(view.clone());
        }
        if state.object_receives.len() >= MAX_OBJECT_RECEIVES {
            return Err(FederationError::Capacity);
        }
        let next = state
            .next_object_receive_id
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        let transfer = transfer_id(next);
        let view = ObjectReceiveView {
            transfer,
            spec,
            phase: ObjectReceivePhase::Pending,
            revision: 1,
        };
        state.object_receives.insert(transfer, view.clone());
        state.next_object_receive_id = next;
        Ok(view)
    }

    fn object_receive(
        &self,
        transfer: ObjectTransferId,
    ) -> Result<Option<ObjectReceiveView>, FederationError> {
        Ok(self.lock()?.object_receives.get(&transfer).cloned())
    }

    fn mark_object_verified(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
        blob: &BlobRef,
    ) -> Result<ObjectReceiveView, FederationError> {
        let mut state = self.lock()?;
        let view = state
            .object_receives
            .get_mut(&transfer)
            .ok_or(FederationError::NotFound)?;
        if &view.spec.blob != blob {
            return Err(FederationError::Conflict);
        }
        if view.phase != ObjectReceivePhase::Pending {
            if expected_revision == 1 || expected_revision == view.revision {
                return Ok(view.clone());
            }
            return Err(FederationError::Conflict);
        }
        if expected_revision != 1 {
            return Err(FederationError::Conflict);
        }
        view.phase = ObjectReceivePhase::Verified;
        view.revision = 2;
        Ok(view.clone())
    }

    fn mark_object_bound(
        &self,
        evidence: ObjectReferenceEvidence,
    ) -> Result<ObjectReceiveView, FederationError> {
        let mut state = self.lock()?;
        let view = state
            .object_receives
            .get_mut(&evidence.transfer())
            .ok_or(FederationError::NotFound)?;
        if view.spec != *evidence.spec() {
            return Err(FederationError::Conflict);
        }
        if view.phase == ObjectReceivePhase::Bound {
            if evidence.expected_revision() == 2 || evidence.expected_revision() == 3 {
                return Ok(view.clone());
            }
            return Err(FederationError::Conflict);
        }
        if view.phase != ObjectReceivePhase::Verified
            || evidence.expected_revision() != view.revision
        {
            return Err(FederationError::Conflict);
        }
        view.phase = ObjectReceivePhase::Bound;
        view.revision = 3;
        Ok(view.clone())
    }

    fn retire_bound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError> {
        let mut state = self.lock()?;
        let view = state
            .object_receives
            .get(&transfer)
            .ok_or(FederationError::NotFound)?;
        if view.phase != ObjectReceivePhase::Bound || view.revision != expected_revision {
            return Err(FederationError::Conflict);
        }
        state.object_receives.remove(&transfer);
        Ok(())
    }

    fn retire_unbound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError> {
        let mut state = self.lock()?;
        let view = state
            .object_receives
            .get(&transfer)
            .ok_or(FederationError::NotFound)?;
        if view.phase == ObjectReceivePhase::Bound || view.revision != expected_revision {
            return Err(FederationError::Conflict);
        }
        state.object_receives.remove(&transfer);
        Ok(())
    }

    fn reserve_receive_gc(&self, blob: &BlobRef) -> Result<ObjectGcFence, FederationError> {
        if !BlobRef::is_valid_hash(&blob.hash) {
            return Err(FederationError::Invalid("invalid object hash"));
        }
        let mut state = self.lock()?;
        if state.object_gc_fences.contains_key(&blob.hash)
            || state
                .object_receives
                .values()
                .any(|view| view.spec.blob.hash == blob.hash)
        {
            return Err(FederationError::Conflict);
        }
        if state.object_gc_fences.len() >= MAX_OBJECT_GC_FENCES {
            return Err(FederationError::Capacity);
        }
        let generation = state
            .next_object_gc_fence_id
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        state.object_gc_fences.insert(blob.hash.clone(), generation);
        state.next_object_gc_fence_id = generation;
        Ok(ObjectGcFence {
            hash: blob.hash.clone(),
            generation,
        })
    }

    fn receive_gc_fence(&self, hash: &str) -> Result<Option<ObjectGcFence>, FederationError> {
        if !BlobRef::is_valid_hash(hash) {
            return Err(FederationError::Invalid("invalid object hash"));
        }
        Ok(self
            .lock()?
            .object_gc_fences
            .get(hash)
            .map(|generation| ObjectGcFence {
                hash: hash.to_owned(),
                generation: *generation,
            }))
    }

    fn active_receive_gc_fences(&self) -> Result<Vec<ObjectGcFence>, FederationError> {
        let state = self.lock()?;
        let mut fences: Vec<_> = state
            .object_gc_fences
            .iter()
            .map(|(hash, generation)| ObjectGcFence {
                hash: hash.clone(),
                generation: *generation,
            })
            .collect();
        fences.sort_unstable_by(|left, right| left.hash.cmp(&right.hash));
        Ok(fences)
    }

    fn release_receive_gc(&self, fence: &ObjectGcFence) -> Result<(), FederationError> {
        if !BlobRef::is_valid_hash(&fence.hash) || fence.generation == 0 {
            return Err(FederationError::Invalid("invalid object GC fence"));
        }
        let mut state = self.lock()?;
        match state.object_gc_fences.get(&fence.hash) {
            Some(generation) if *generation == fence.generation => {
                state.object_gc_fences.remove(&fence.hash);
                Ok(())
            }
            Some(_) => Err(FederationError::Conflict),
            None => Err(FederationError::NotFound),
        }
    }
}
