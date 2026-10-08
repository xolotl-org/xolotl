//! Volatile reference implementation of explicit replica commitments.
//! Snapshot offers and their publisher pins are available only in the durable
//! backend; this store has no snapshot-publisher interface to coordinate.

use super::{MemoryFederationStore, State, authority};
use crate::{
    FederationError, FederationNodeId, FederationReplicaRetentionStore, FederationSubject,
    MAX_REPLICA_LEASE_MS, MAX_REPLICA_MEMBERS, MAX_RETIRE_BYTES, MAX_RETIRE_RECORDS, Position,
    PublishedRetirement, ReplicaMemberSpec, ReplicaMemberView, ReplicaRetentionTerm, StreamRef,
    SubscriptionRef,
};

#[derive(Clone, Copy)]
pub(super) struct ReplicaMember {
    spec: ReplicaMemberSpec,
    revision: u64,
    retired: bool,
}

fn check_time(state: &State, now_ms: u64) -> Result<(), FederationError> {
    if now_ms < state.object_trusted_time_ms {
        Err(FederationError::ClockRollback)
    } else {
        Ok(())
    }
}

fn validate_term(term: ReplicaRetentionTerm, now_ms: u64) -> Result<(), FederationError> {
    if let ReplicaRetentionTerm::LeaseUntilMs(deadline) = term {
        let remaining = deadline
            .checked_sub(now_ms)
            .ok_or(FederationError::Conflict)?;
        if remaining == 0 || remaining > MAX_REPLICA_LEASE_MS {
            return Err(FederationError::Invalid("invalid replica lease deadline"));
        }
    }
    Ok(())
}

fn subscription_receipt(
    state: &State,
    stream: StreamRef,
    member: FederationNodeId,
    subscription: SubscriptionRef,
    require_live: bool,
) -> Result<(Option<Position>, Option<Position>), FederationError> {
    let row = state
        .published_subscriptions
        .get(&subscription)
        .ok_or(FederationError::Corrupt)?;
    if subscription.subscriber != member
        || row.result.subscription != subscription
        || row.result.stream != stream
        || row.request.subscription != subscription
        || row.request.stream != stream
        || row.request.authenticated_subscriber != member
        || row.subject != FederationSubject::Node(member)
    {
        return Err(FederationError::Corrupt);
    }
    if require_live && row.closed_revision.is_some() {
        return Err(FederationError::Conflict);
    }
    if row.acknowledged.is_some_and(|ack| {
        row.result
            .start
            .is_some_and(|start| ack.sequence() <= start.sequence())
    }) {
        return Err(FederationError::Corrupt);
    }
    Ok((row.result.start, row.acknowledged))
}

fn view(state: &State, member: ReplicaMember) -> Result<ReplicaMemberView, FederationError> {
    let (baseline, acknowledged) = subscription_receipt(
        state,
        member.spec.stream,
        member.spec.member,
        member.spec.subscription,
        false,
    )?;
    Ok(ReplicaMemberView {
        spec: member.spec,
        revision: member.revision,
        baseline,
        acknowledged,
        snapshot_covered: None,
        retired: member.retired,
    })
}

fn expired(member: ReplicaMember, now_ms: u64) -> bool {
    !member.retired
        && matches!(member.spec.term, ReplicaRetentionTerm::LeaseUntilMs(deadline) if now_ms >= deadline)
}

/// `expiry_at` is used only by safe maintenance after its time and revision
/// checks. Direct retirement never ignores an elapsed, uncommitted lease.
fn active_frontier(
    state: &State,
    stream: StreamRef,
    expiry_at: Option<u64>,
) -> Result<Option<Option<Position>>, FederationError> {
    let mut lowest: Option<Option<Position>> = None;
    let mut count = 0;
    for ((candidate, _), member) in &state.replica_members {
        if *candidate != stream {
            continue;
        }
        count += 1;
        if count > MAX_REPLICA_MEMBERS || member.revision == 0 {
            return Err(FederationError::Corrupt);
        }
        if member.retired || expiry_at.is_some_and(|now_ms| expired(*member, now_ms)) {
            continue;
        }
        let member_view = view(state, *member)?;
        let frontier = member_view.acknowledged.or(member_view.baseline);
        lowest = Some(match (lowest, frontier) {
            (None, frontier) => frontier,
            (Some(None), _) | (_, None) => None,
            (Some(Some(old)), Some(current)) if old.sequence() <= current.sequence() => Some(old),
            (Some(Some(_)), Some(current)) => Some(current),
        });
    }
    Ok(lowest)
}

fn permitted_through(
    state: &State,
    stream: StreamRef,
    through: Position,
    expiry_at: Option<u64>,
) -> Result<(), FederationError> {
    if let Some(frontier) = active_frontier(state, stream, expiry_at)? {
        let Some(frontier) = frontier else {
            return Err(FederationError::Conflict);
        };
        if through.sequence() > frontier.sequence()
            || (through.sequence() == frontier.sequence() && through.digest() != frontier.digest())
        {
            return Err(FederationError::Conflict);
        }
    }
    Ok(())
}

struct RetirePlan {
    stream: StreamRef,
    through: Option<Position>,
    head: Option<Position>,
    next: u64,
    count: usize,
}

fn plan_retirement(
    state: &State,
    local: FederationNodeId,
    stream: StreamRef,
    through: Position,
    max_records: usize,
    expiry_at: Option<u64>,
) -> Result<RetirePlan, FederationError> {
    if stream.publisher != local {
        return Err(FederationError::Unauthorized);
    }
    if max_records == 0 || max_records > MAX_RETIRE_RECORDS {
        return Err(FederationError::Capacity);
    }
    let published = state
        .streams
        .get(&stream)
        .ok_or(FederationError::NotFound)?;
    if published.retired_through == Some(through) {
        return Ok(RetirePlan {
            stream,
            through: published.retired_through,
            head: published.head,
            next: published.minimum_available,
            count: 0,
        });
    }
    permitted_through(state, stream, through, expiry_at)?;
    published.at(through)?;
    let count = through
        .sequence()
        .checked_sub(published.minimum_available)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(FederationError::Capacity)?;
    if count > max_records {
        return Err(FederationError::Capacity);
    }
    let bytes = published
        .records
        .iter()
        .take(count)
        .try_fold(0usize, |used, record| {
            used.checked_add(record.payload().len())
                .ok_or(FederationError::Capacity)
        })?;
    if bytes > MAX_RETIRE_BYTES {
        return Err(FederationError::Capacity);
    }
    let next = through
        .sequence()
        .checked_add(1)
        .ok_or(FederationError::Capacity)?;
    Ok(RetirePlan {
        stream,
        through: Some(through),
        head: published.head,
        next,
        count,
    })
}

fn apply_retirement(
    state: &mut State,
    plan: RetirePlan,
) -> Result<PublishedRetirement, FederationError> {
    if plan.count != 0 {
        let published = state
            .streams
            .get_mut(&plan.stream)
            .ok_or(FederationError::Corrupt)?;
        published.records.drain(..plan.count);
        published.minimum_available = plan.next;
        published.retired_through = plan.through;
    }
    Ok(PublishedRetirement {
        stream: plan.stream,
        head: plan.head,
        minimum_available: plan.next,
        retired_through: plan.through,
        removed: plan.count,
    })
}

pub(super) fn retire_explicit(
    state: &mut State,
    local: FederationNodeId,
    stream: StreamRef,
    through: Position,
    max_records: usize,
) -> Result<PublishedRetirement, FederationError> {
    let plan = plan_retirement(state, local, stream, through, max_records, None)?;
    apply_retirement(state, plan)
}

impl FederationReplicaRetentionStore for MemoryFederationStore {
    fn local_node(&self) -> FederationNodeId {
        self.local_node
    }

    fn join_replica(
        &self,
        spec: ReplicaMemberSpec,
        expected_revision: Option<u64>,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError> {
        if spec.stream.publisher != self.local_node
            || spec.member == self.local_node
            || spec.subscription.subscriber != spec.member
        {
            return Err(FederationError::Unauthorized);
        }
        validate_term(spec.term, now_ms)?;
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        check_time(&state, now_ms)?;
        let stream = state
            .streams
            .get(&spec.stream)
            .ok_or(FederationError::NotFound)?;
        let previous = state.replica_members.get(&(spec.stream, spec.member));
        let revision = match (previous, expected_revision) {
            (None, None) => 1,
            (Some(previous), Some(expected))
                if previous.retired
                    && previous.revision == expected
                    && previous.spec.subscription != spec.subscription =>
            {
                previous
                    .revision
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?
            }
            _ => return Err(FederationError::Conflict),
        };
        if previous.is_none()
            && state
                .replica_members
                .keys()
                .filter(|(candidate, _)| *candidate == spec.stream)
                .count()
                >= MAX_REPLICA_MEMBERS
        {
            return Err(FederationError::Capacity);
        }
        let (baseline, acknowledged) =
            subscription_receipt(&state, spec.stream, spec.member, spec.subscription, true)?;
        let frontier = acknowledged.or(baseline);
        if frontier.map_or(0, Position::sequence) < stream.minimum_available.saturating_sub(1) {
            return Err(FederationError::ResyncRequired {
                minimum_available: stream.minimum_available,
            });
        }
        if let Some(frontier) = frontier
            && stream.retired_through.is_some_and(|anchor| {
                frontier.sequence() == anchor.sequence() && frontier.digest() != anchor.digest()
            })
        {
            return Err(FederationError::Conflict);
        }
        let subscription = state
            .published_subscriptions
            .get(&spec.subscription)
            .ok_or(FederationError::Corrupt)?;
        if authority(&state, spec.member, &subscription.result.export, true)?
            != subscription.result.publisher_authority
        {
            return Err(FederationError::Conflict);
        }
        state.replica_members.insert(
            (spec.stream, spec.member),
            ReplicaMember {
                spec,
                revision,
                retired: false,
            },
        );
        state.object_trusted_time_ms = now_ms;
        Ok(ReplicaMemberView {
            spec,
            revision,
            baseline,
            acknowledged,
            snapshot_covered: None,
            retired: false,
        })
    }

    fn extend_replica(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
        expected_revision: u64,
        term: ReplicaRetentionTerm,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        validate_term(term, now_ms)?;
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        check_time(&state, now_ms)?;
        let old = *state
            .replica_members
            .get(&(stream, member))
            .ok_or(FederationError::NotFound)?;
        if old.retired || old.revision != expected_revision {
            return Err(FederationError::Conflict);
        }
        match (old.spec.term, term) {
            (ReplicaRetentionTerm::Permanent, ReplicaRetentionTerm::Permanent) => {}
            (ReplicaRetentionTerm::Permanent, _) => return Err(FederationError::Conflict),
            (ReplicaRetentionTerm::LeaseUntilMs(deadline), _) if now_ms >= deadline => {
                return Err(FederationError::Conflict);
            }
            (ReplicaRetentionTerm::LeaseUntilMs(old), ReplicaRetentionTerm::LeaseUntilMs(next))
                if next <= old =>
            {
                return Err(FederationError::Conflict);
            }
            _ => {}
        }
        let revision = old
            .revision
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        let updated = ReplicaMember {
            spec: ReplicaMemberSpec { term, ..old.spec },
            revision,
            ..old
        };
        let result = view(&state, updated)?;
        state.replica_members.insert((stream, member), updated);
        state.object_trusted_time_ms = now_ms;
        Ok(result)
    }

    fn retire_replica(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
        expected_revision: u64,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        check_time(&state, now_ms)?;
        let old = *state
            .replica_members
            .get(&(stream, member))
            .ok_or(FederationError::NotFound)?;
        if old.retired || old.revision != expected_revision {
            return Err(FederationError::Conflict);
        }
        let revision = old
            .revision
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        let updated = ReplicaMember {
            revision,
            retired: true,
            ..old
        };
        let result = view(&state, updated)?;
        state.replica_members.insert((stream, member), updated);
        state.object_trusted_time_ms = now_ms;
        Ok(result)
    }

    fn replica_member(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
    ) -> Result<Option<ReplicaMemberView>, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let state = self.lock()?;
        state
            .replica_members
            .get(&(stream, member))
            .copied()
            .map(|member| view(&state, member))
            .transpose()
    }

    fn scan_replica_members(
        &self,
        stream: StreamRef,
        after: Option<FederationNodeId>,
        max: usize,
    ) -> Result<Vec<ReplicaMemberView>, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        if max == 0 || max > MAX_REPLICA_MEMBERS {
            return Err(FederationError::Capacity);
        }
        let state = self.lock()?;
        let mut members = state
            .replica_members
            .iter()
            .filter(|((candidate, member), _)| {
                *candidate == stream && after.is_none_or(|after| *member > after)
            })
            .map(|((_, member), row)| (*member, *row))
            .collect::<Vec<_>>();
        members.sort_unstable_by_key(|(member, _)| *member);
        members
            .into_iter()
            .take(max)
            .map(|(_, row)| view(&state, row))
            .collect()
    }

    fn retire_replica_safe_history(
        &self,
        stream: StreamRef,
        now_ms: u64,
        max_records: usize,
    ) -> Result<PublishedRetirement, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        if max_records == 0 || max_records > MAX_RETIRE_RECORDS {
            return Err(FederationError::Capacity);
        }
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        check_time(&state, now_ms)?;
        let published = state
            .streams
            .get(&stream)
            .ok_or(FederationError::NotFound)?;
        let expiry = state
            .replica_members
            .iter()
            .filter(|((candidate, _), member)| *candidate == stream && expired(**member, now_ms))
            .map(|(key, member)| {
                member
                    .revision
                    .checked_add(1)
                    .map(|revision| (*key, revision))
                    .ok_or(FederationError::Capacity)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let frontier = active_frontier(&state, stream, Some(now_ms))?;
        let mut end = published.head.map_or(0, Position::sequence);
        if let Some(frontier) = frontier {
            end = end.min(frontier.map_or(0, Position::sequence));
        }
        end = end.min(
            published
                .minimum_available
                .saturating_add(max_records as u64 - 1),
        );
        let mut last = None;
        let mut bytes = 0usize;
        for record in published.records.iter().take(max_records) {
            if record.sequence() > end {
                break;
            }
            let next = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Capacity)?;
            if next > MAX_RETIRE_BYTES {
                break;
            }
            bytes = next;
            last = Some(record.position());
        }
        let plan = last
            .map(|last| {
                plan_retirement(
                    &state,
                    self.local_node,
                    stream,
                    last,
                    max_records,
                    Some(now_ms),
                )
            })
            .transpose()?;
        let result = if let Some(plan) = plan {
            apply_retirement(&mut state, plan)?
        } else {
            PublishedRetirement {
                stream,
                head: published.head,
                minimum_available: published.minimum_available,
                retired_through: published.retired_through,
                removed: 0,
            }
        };
        for (key, revision) in expiry {
            let member = state
                .replica_members
                .get_mut(&key)
                .ok_or(FederationError::Corrupt)?;
            member.revision = revision;
            member.retired = true;
        }
        state.object_trusted_time_ms = now_ms;
        Ok(result)
    }
}
