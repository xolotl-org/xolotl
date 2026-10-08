use super::*;
use crate::{
    FederationObjectReadStore, MAX_OBJECT_GRANTS, MAX_OBJECT_TRANSFERS, ObjectGrantId,
    ObjectGrantSpec, ObjectGrantView, ObjectReadAdmission, ObjectReadAuthority, ObjectReadRequest,
};

fn check_time(state: &State, now_ms: u64) -> Result<(), FederationError> {
    if now_ms < state.object_trusted_time_ms {
        return Err(FederationError::ClockRollback);
    }
    Ok(())
}

fn check_peer(state: &State, peer: FederationNodeId) -> Result<(), FederationError> {
    if state.peers.get(&peer).is_some_and(|row| !row.enabled) {
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

fn check_read_peer(
    state: &State,
    request: &ObjectReadRequest,
    authority: ObjectReadAuthority,
    now_ms: u64,
) -> Result<(), FederationError> {
    authority.check_request(request, now_ms)?;
    let peer = request.authenticated_presenter;
    let proof = authority.proof();
    let allowed = match authority.admission() {
        ObjectReadAdmission::Private => {
            state.peers.get(&peer).is_some_and(|row| row.enabled)
                && state.admissions.get(&peer).is_some_and(|(_, policy)| {
                    proof.online_generation() >= policy.minimum_online_generation
                        && policy
                            .allowed_authorization_digests
                            .contains(&proof.authorization_digest())
                })
        }
        ObjectReadAdmission::Unconfigured => {
            !state.peers.contains_key(&peer) && !state.admissions.contains_key(&peer)
        }
    };
    if !allowed {
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

fn check_request(
    view: &ObjectGrantView,
    request: &ObjectReadRequest,
    now_ms: u64,
) -> Result<(), FederationError> {
    if !view.enabled
        || now_ms >= view.spec.expires_at_ms
        || view.spec.presenter != request.authenticated_presenter
        || view.spec.subject != request.subject
        || view.spec.blob != request.blob
    {
        return Err(FederationError::Unauthorized);
    }
    if view.revision != request.expected_revision {
        return Err(FederationError::Conflict);
    }
    let end = request
        .offset
        .checked_add(u64::try_from(request.max_bytes).map_err(|_error| FederationError::Capacity)?)
        .ok_or(FederationError::Capacity)?;
    if request.offset < view.spec.range_start || end > view.spec.range_end {
        return Err(FederationError::Unauthorized);
    }
    if request.max_bytes > view.spec.max_chunk_bytes {
        return Err(FederationError::Capacity);
    }
    Ok(())
}

impl FederationObjectReadStore for MemoryFederationStore {
    fn authorize_object_delivery(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(request.authenticated_presenter)?;
        request.validate(self.local_node)?;
        let (state, now_ms) = self.delivery_lock(now_ms)?;
        confirm_read(&state, request, authority, now_ms)
    }

    fn bind_object_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReadStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.local_node
    }

    fn issue_object_grant(
        &self,
        spec: ObjectGrantSpec,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        spec.validate(self.local_node)?;
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        check_time(&state, now_ms)?;
        check_peer(&state, spec.presenter)?;
        if now_ms >= spec.expires_at_ms {
            return Err(FederationError::Unauthorized);
        }
        if state.object_grants.len() >= MAX_OBJECT_GRANTS {
            return Err(FederationError::Capacity);
        }
        let next = state
            .next_object_grant_id
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        let id = ObjectGrantId::new(next)?;
        let view = ObjectGrantView {
            id,
            spec,
            revision: 1,
            enabled: true,
            charged_bytes: 0,
        };
        state.object_grants.insert(id, view.clone());
        state.next_object_grant_id = next;
        state.object_trusted_time_ms = now_ms;
        Ok(view)
    }

    fn object_grant(&self, id: ObjectGrantId) -> Result<Option<ObjectGrantView>, FederationError> {
        Ok(self.lock()?.object_grants.get(&id).cloned())
    }

    fn list_object_grants(&self) -> Result<Vec<ObjectGrantView>, FederationError> {
        let mut grants: Vec<_> = self.lock()?.object_grants.values().cloned().collect();
        grants.sort_by_key(|view| view.id);
        Ok(grants)
    }

    fn revoke_object_grant(
        &self,
        id: ObjectGrantId,
        expected_revision: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        let mut state = self.lock()?;
        let view = state
            .object_grants
            .get_mut(&id)
            .ok_or(FederationError::NotFound)?;
        if view.revision != expected_revision || !view.enabled {
            return Err(FederationError::Conflict);
        }
        view.enabled = false;
        view.revision = view
            .revision
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        Ok(view.clone())
    }

    fn reserve_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        self.decision_peer(request.authenticated_presenter)?;
        request.validate(self.local_node)?;
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        check_time(&state, now_ms)?;
        check_read_peer(&state, request, authority, now_ms)?;
        let view = state
            .object_grants
            .get(&request.grant)
            .ok_or(FederationError::Unauthorized)?;
        check_request(view, request, now_ms)?;
        let next = view
            .charged_bytes
            .checked_add(
                u64::try_from(request.max_bytes).map_err(|_error| FederationError::Capacity)?,
            )
            .filter(|charged| *charged <= view.spec.max_total_bytes)
            .ok_or(FederationError::Capacity)?;
        let key = (request.authenticated_presenter, request.transfer);
        let binding = (
            request.grant,
            request.expected_revision,
            view.spec.expires_at_ms,
        );
        match state.object_transfers.get(&key) {
            Some(previous) if *previous != binding => return Err(FederationError::Conflict),
            None if state.object_transfers.len() >= MAX_OBJECT_TRANSFERS => {
                return Err(FederationError::Capacity);
            }
            _ => {}
        }
        state.object_transfers.insert(key, binding);
        let view = state
            .object_grants
            .get_mut(&request.grant)
            .ok_or(FederationError::Corrupt)?;
        view.charged_bytes = next;
        let result = view.clone();
        state.object_trusted_time_ms = now_ms;
        Ok(result)
    }

    fn confirm_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(request.authenticated_presenter)?;
        request.validate(self.local_node)?;
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        confirm_read(&state, request, authority, now_ms)?;
        state.object_trusted_time_ms = now_ms;
        Ok(())
    }

    fn retire_object_grants(&self, now_ms: u64, limit: usize) -> Result<usize, FederationError> {
        if limit == 0 || limit > 256 {
            return Err(FederationError::Capacity);
        }
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        check_time(&state, now_ms)?;
        let expired: Vec<_> = state
            .object_grants
            .iter()
            .filter(|(_, view)| now_ms >= view.spec.expires_at_ms)
            .map(|(id, _)| *id)
            .take(limit)
            .collect();
        for id in &expired {
            state.object_grants.remove(id);
        }
        state
            .object_transfers
            .retain(|_, (_, _, expiry)| *expiry > now_ms);
        state.object_trusted_time_ms = now_ms;
        Ok(expired.len())
    }
}

fn confirm_read(
    state: &State,
    request: &ObjectReadRequest,
    authority: ObjectReadAuthority,
    now_ms: u64,
) -> Result<(), FederationError> {
    check_time(state, now_ms)?;
    check_read_peer(state, request, authority, now_ms)?;
    let view = state
        .object_grants
        .get(&request.grant)
        .ok_or(FederationError::Unauthorized)?;
    check_request(view, request, now_ms)?;
    if state
        .object_transfers
        .get(&(request.authenticated_presenter, request.transfer))
        != Some(&(
            request.grant,
            request.expected_revision,
            view.spec.expires_at_ms,
        ))
    {
        return Err(FederationError::Conflict);
    }
    Ok(())
}
