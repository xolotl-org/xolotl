use super::*;
use crate::{
    FederationPublicReadStore, MAX_PUBLIC_POLICIES, PublicReadPage, PublicReadRequest,
    PublicStreamPolicy, PublicStreamView,
};

impl FederationPublicReadStore for MemoryFederationStore {
    fn authorize_public_delivery(
        &self,
        reader: FederationNodeId,
        stream: StreamRef,
        revision: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(reader)?;
        let (state, _) = self.delivery_lock(0)?;
        check_public_reader(&state, reader)?;
        let policy = state
            .public_policies
            .get(&stream)
            .filter(|policy| policy.enabled)
            .ok_or(FederationError::Unauthorized)?;
        if policy.revision != revision {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }

    fn bind_public_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationPublicReadStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.local_node
    }

    fn public_stream_policy(
        &self,
        stream: StreamRef,
    ) -> Result<Option<(PublicStreamPolicy, u64)>, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Invalid(
                "public stream has another publisher",
            ));
        }
        let state = self.lock()?;
        Ok(state.public_policies.get(&stream).map(|row| {
            (
                PublicStreamPolicy {
                    stream,
                    enabled: row.enabled,
                    max_read_records: row.max_read_records,
                    max_read_bytes: row.max_read_bytes,
                },
                row.revision,
            )
        }))
    }

    fn list_public_stream_policies(
        &self,
    ) -> Result<Vec<(PublicStreamPolicy, u64)>, FederationError> {
        let state = self.lock()?;
        Ok(state
            .public_policies
            .iter()
            .map(|(stream, row)| {
                (
                    PublicStreamPolicy {
                        stream: *stream,
                        enabled: row.enabled,
                        max_read_records: row.max_read_records,
                        max_read_bytes: row.max_read_bytes,
                    },
                    row.revision,
                )
            })
            .collect())
    }

    fn set_public_stream_policy(
        &self,
        expected_revision: Option<u64>,
        policy: PublicStreamPolicy,
    ) -> Result<PublicStreamView, FederationError> {
        policy.validate(self.local_node)?;
        let mut state = self.lock()?;
        let stream = state
            .streams
            .get(&policy.stream)
            .ok_or(FederationError::NotFound)?;
        let export = stream.spec.export.clone();
        let head = stream.head;
        let minimum_available = stream.minimum_available;
        let current = state.public_policies.get(&policy.stream);
        let revision = next_revision(current.map(|row| row.revision), expected_revision)?;
        if let Some(current) = current {
            if !current.enabled && policy.enabled {
                return Err(FederationError::Conflict);
            }
        } else if !policy.enabled || head.is_some() {
            return Err(FederationError::Invalid(
                "public policy must begin on an empty stream",
            ));
        }
        if current.is_none() && state.public_policies.len() >= MAX_PUBLIC_POLICIES {
            return Err(FederationError::Capacity);
        }
        state.public_policies.insert(
            policy.stream,
            PublicPolicyRow {
                revision,
                enabled: policy.enabled,
                max_read_records: policy.max_read_records,
                max_read_bytes: policy.max_read_bytes,
            },
        );
        Ok(PublicStreamView {
            stream: policy.stream,
            export,
            policy_revision: revision,
            head,
            minimum_available,
            max_read_records: policy.max_read_records,
            max_read_bytes: policy.max_read_bytes,
        })
    }

    fn inspect_public_stream(
        &self,
        authenticated_reader: FederationNodeId,
        stream: StreamRef,
    ) -> Result<PublicStreamView, FederationError> {
        self.decision_peer(authenticated_reader)?;
        if authenticated_reader == self.local_node || stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let state = self.lock()?;
        check_public_reader(&state, authenticated_reader)?;
        let policy = state
            .public_policies
            .get(&stream)
            .filter(|policy| policy.enabled)
            .ok_or(FederationError::Unauthorized)?;
        let published = state.streams.get(&stream).ok_or(FederationError::Corrupt)?;
        Ok(PublicStreamView {
            stream,
            export: published.spec.export.clone(),
            policy_revision: policy.revision,
            head: published.head,
            minimum_available: published.minimum_available,
            max_read_records: policy.max_read_records,
            max_read_bytes: policy.max_read_bytes,
        })
    }

    fn read_public_stream(
        &self,
        request: PublicReadRequest,
    ) -> Result<PublicReadPage, FederationError> {
        request.validate(self.local_node)?;
        let state = self.lock()?;
        check_public_reader(&state, request.authenticated_reader)?;
        let policy = state
            .public_policies
            .get(&request.stream)
            .filter(|policy| policy.enabled)
            .ok_or(FederationError::Unauthorized)?;
        if request.expected_policy_revision != policy.revision {
            return Err(FederationError::Conflict);
        }
        if request.max_records > policy.max_read_records
            || request.max_bytes > policy.max_read_bytes
        {
            return Err(FederationError::Capacity);
        }
        let published = state
            .streams
            .get(&request.stream)
            .ok_or(FederationError::Corrupt)?;
        let first = if let Some(after) = request.after {
            published.at(after)?;
            after
                .sequence()
                .checked_add(1)
                .ok_or(FederationError::Capacity)?
        } else {
            published.minimum_available
        };
        let offset = first
            .checked_sub(published.minimum_available)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(FederationError::Capacity)?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for record in published
            .records
            .iter()
            .skip(offset)
            .take(request.max_records)
        {
            let next = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Capacity)?;
            if next > request.max_bytes {
                if records.is_empty() {
                    return Err(FederationError::Capacity);
                }
                break;
            }
            bytes = next;
            records.push(record.clone());
        }
        Ok(PublicReadPage {
            policy_revision: policy.revision,
            records,
            head: published.head,
            minimum_available: published.minimum_available,
        })
    }
}

fn check_public_reader(
    state: &State,
    authenticated_reader: FederationNodeId,
) -> Result<(), FederationError> {
    if state.peers.contains_key(&authenticated_reader) {
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}
