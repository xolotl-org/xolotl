//! Source metadata is private to this storage owner. The declared State sink
//! and these maps are changed under the same journal write guard.

use super::{InMemoryBackend, MemoryHistory, Notification, now_millis};
use crate::StateEvent;
use std::collections::BTreeMap;
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, ExternalInstallationRecord,
    ExternalInstallationRevision, MAX_DECLARED_SINK_BYTES, MAX_ID_BYTES,
    MAX_INSTALLATION_RECORD_BYTES, MAX_MAINTENANCE_BATCH, MAX_RATE_HITS, MAX_RECEIPT_BYTES,
    MAX_SINK_EVENTS, SourceAdmissionError, SourceClaimEvidence, SourceClaimInspection,
    SourceCommit, SourceCommitOutcome, SourceCommitRejection, SourceDeclarationAdmission,
    SourceEventCommit, SourceEventDecisionInspection, SourceEventMaintenance,
    SourceEvidenceInspection, SourceFuture, SourceMaintenance, SourceMaintenanceResult,
    SourceReceipt, SourceStoreError, SourceStreamLifecycle, SourceStreamOpen,
    SourceStreamOpenOutcome, SourceStreamRetire, SourceStreamRetireOutcome, SourceStreamScope,
    SourceStreamSnapshot, SourceStreamState,
};
use xolotl_types::{
    Value, ValueView,
    external::{EventSource, ExternalInstallationDef, OverflowPolicy},
};

#[derive(Default)]
pub(super) struct SourceMemory {
    installations: BTreeMap<String, ExternalInstallationRecord>,
    next_authority_epoch: u64,
    decision_time_floors: BTreeMap<u64, i64>,
    stream_revisions: BTreeMap<Vec<u8>, u64>,
    events: BTreeMap<Vec<u8>, AcceptedEvent>,
    sequences: BTreeMap<Vec<u8>, SourceStreamState>,
    rates: BTreeMap<Vec<u8>, RateRecord>,
    receipts: BTreeMap<Vec<u8>, SourceReceipt>,
    cursor: Option<Vec<u8>>,
}

struct AcceptedEvent {
    claim_id: xolotl_source::SourceClaimId,
    expires_at_ms: i64,
    payload_digest: [u8; 32],
    stream: Option<AcceptedStream>,
}

struct AcceptedStream {
    stream_id: String,
    seq: u64,
}

struct RateRecord {
    window_ms: u64,
    hits: Vec<i64>,
}

fn aborted(message: impl Into<String>) -> SourceStoreError {
    SourceStoreError::Aborted(message.into())
}

fn segment(key: &mut Vec<u8>, segment: &str) -> Result<(), SourceStoreError> {
    if segment.is_empty() || segment.len() > MAX_ID_BYTES {
        return Err(aborted("Source identity is invalid"));
    }
    let len = u32::try_from(segment.len()).map_err(|_error| aborted("Source identity too long"))?;
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(segment.as_bytes());
    Ok(())
}

fn scope_key(
    kind: u8,
    installation_id: &str,
    projection_id: &str,
) -> Result<Vec<u8>, SourceStoreError> {
    if installation_id.is_empty()
        || projection_id.is_empty()
        || installation_id.len() > MAX_ID_BYTES
        || projection_id.len() > MAX_ID_BYTES
    {
        return Err(aborted("Source scope identity is invalid"));
    }
    let mut key = Vec::with_capacity(1 + 8 + installation_id.len() + projection_id.len());
    key.push(kind);
    segment(&mut key, installation_id)?;
    segment(&mut key, projection_id)?;
    Ok(key)
}

fn event_key_for(
    installation_id: &str,
    projection_id: &str,
    scope_epoch: u64,
    stream_epoch: Option<u64>,
    event_id: &str,
) -> Result<Vec<u8>, SourceStoreError> {
    if scope_epoch == 0 || stream_epoch == Some(0) {
        return Err(aborted("Source scope or stream epoch is invalid"));
    }
    let mut key = scope_key(b'E', installation_id, projection_id)?;
    key.extend_from_slice(&scope_epoch.to_be_bytes());
    key.push(u8::from(stream_epoch.is_some()));
    if let Some(epoch) = stream_epoch {
        key.extend_from_slice(&epoch.to_be_bytes());
    }
    segment(&mut key, event_id)?;
    Ok(key)
}

fn event_key(request: &SourceCommit<'_>) -> Result<Vec<u8>, SourceStoreError> {
    event_key_for(
        request.claim.installation_id,
        request.claim.projection_id,
        request.claim.scope_epoch,
        request.claim.stream_epoch,
        request.claim.event_id,
    )
}

fn claim_key(claim: xolotl_source::SourceClaim<'_>) -> Result<Vec<u8>, SourceStoreError> {
    let mut key = scope_key(b'C', claim.installation_id, claim.projection_id)?;
    key.extend_from_slice(&claim.scope_epoch.to_be_bytes());
    key.push(u8::from(claim.stream_epoch.is_some()));
    if let Some(epoch) = claim.stream_epoch {
        key.extend_from_slice(&epoch.to_be_bytes());
    }
    segment(&mut key, claim.event_id)?;
    key.extend_from_slice(claim.claim_id.as_bytes());
    Ok(key)
}

fn stream_key(request: &SourceCommit<'_>) -> Result<Option<Vec<u8>>, SourceStoreError> {
    request
        .stream
        .map(|stream| {
            let mut key = scope_key(
                b'S',
                request.claim.installation_id,
                request.claim.projection_id,
            )?;
            key.extend_from_slice(&request.claim.scope_epoch.to_be_bytes());
            segment(&mut key, stream.stream_id)?;
            Ok(key)
        })
        .transpose()
}

fn stream_scope_key(stream: SourceStreamScope<'_>, kind: u8) -> Result<Vec<u8>, SourceStoreError> {
    xolotl_source::validate_stream_scope(stream)?;
    let mut key = scope_key(kind, stream.installation_id, stream.projection_id)?;
    key.extend_from_slice(&stream.scope_epoch.to_be_bytes());
    if kind == b'S' {
        segment(&mut key, stream.stream_id)?;
    }
    Ok(key)
}

fn active_stream_scope(source: &SourceMemory, stream: SourceStreamScope<'_>) -> bool {
    source
        .installations
        .get(stream.installation_id)
        .and_then(|record| record.scope_epoch(stream.projection_id))
        == Some(stream.scope_epoch)
}

fn revision_key(
    installation_id: &str,
    projection_id: &str,
    scope_epoch: u64,
) -> Result<Vec<u8>, SourceStoreError> {
    let mut key = scope_key(b'V', installation_id, projection_id)?;
    key.extend_from_slice(&scope_epoch.to_be_bytes());
    Ok(key)
}

fn parse_source_scope(key: &[u8]) -> Result<(&str, &str, u64), SourceStoreError> {
    fn take_segment<'a>(key: &mut &'a [u8]) -> Result<&'a str, SourceStoreError> {
        let length = key
            .get(..4)
            .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
        let length = u32::from_be_bytes(
            length
                .try_into()
                .map_err(|_error| aborted("Source metadata key is corrupt"))?,
        ) as usize;
        if length == 0 || length > MAX_ID_BYTES {
            return Err(aborted("Source metadata key is corrupt"));
        }
        let bytes = key
            .get(4..4 + length)
            .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_error| aborted("Source metadata key is corrupt"))?;
        *key = &key[4 + length..];
        Ok(value)
    }
    let mut rest = key
        .get(1..)
        .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
    let installation = take_segment(&mut rest)?;
    let projection = take_segment(&mut rest)?;
    let epoch = rest
        .get(..8)
        .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
    let epoch = u64::from_be_bytes(
        epoch
            .try_into()
            .map_err(|_error| aborted("Source metadata key is corrupt"))?,
    );
    rest = &rest[8..];
    match key.first() {
        Some(b'E') => {
            let ordered = *rest
                .first()
                .ok_or_else(|| aborted("Source event key is corrupt"))?;
            rest = &rest[1..];
            match ordered {
                0 => {}
                1 => {
                    let stream_epoch = rest
                        .get(..8)
                        .ok_or_else(|| aborted("Source event key is corrupt"))?;
                    if stream_epoch == [0; 8] {
                        return Err(aborted("Source event key is corrupt"));
                    }
                    rest = &rest[8..];
                }
                _ => return Err(aborted("Source event key is corrupt")),
            }
            take_segment(&mut rest)?;
        }
        Some(b'S') => {
            take_segment(&mut rest)?;
        }
        Some(b'R') => {}
        _ => return Err(aborted("Source metadata key is corrupt")),
    }
    if epoch == 0 || !rest.is_empty() {
        return Err(aborted("Source metadata key is corrupt"));
    }
    Ok((installation, projection, epoch))
}

fn cutoff(now_millis: i64, window_ms: u64) -> i128 {
    i128::from(now_millis) - i128::from(window_ms)
}

impl InMemoryBackend {
    fn commit_source(
        &self,
        request: SourceCommit<'_>,
    ) -> Result<SourceCommitOutcome, SourceStoreError> {
        xolotl_source::validate_commit(&request)?;
        let Some((_payload_bytes, payload_digest)) =
            crate::host::source_payload_fingerprint_bounded(
                request.payload,
                request.max_inline_payload_bytes,
            )
            .map_err(|_error| aborted("Source payload could not be encoded"))?
        else {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::PayloadTooLarge,
            ));
        };
        let event_key = event_key(&request)?;
        let receipt_key = claim_key(request.claim)?;
        let stream_key = stream_key(&request)?;
        let rate_key = request
            .rate_limit
            .map(|_rule| {
                let mut key = scope_key(
                    b'R',
                    request.claim.installation_id,
                    request.claim.projection_id,
                )?;
                key.extend_from_slice(&request.claim.scope_epoch.to_be_bytes());
                Ok::<_, SourceStoreError>(key)
            })
            .transpose()?;
        let max_events = usize::try_from(request.capacity.max_events)
            .map_err(|_error| aborted("Source capacity exceeds address space"))?;
        if max_events == 0 {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::CapacityExceeded,
            ));
        }
        if max_events > MAX_SINK_EVENTS {
            return Err(aborted("Source sink event capacity exceeds maximum"));
        }
        if request.max_inline_payload_bytes == 0
            || max_events
                .checked_mul(request.max_inline_payload_bytes)
                .is_none_or(|bytes| bytes > MAX_DECLARED_SINK_BYTES)
        {
            return Err(aborted("Source declared sink byte budget exceeds maximum"));
        }
        if request
            .stream
            .is_some_and(|stream| stream.seq > i64::MAX as u64)
        {
            return Err(aborted("Source sequence exceeds supported range"));
        }

        let (drain, displaced) = {
            let mut guard = loop {
                let state = self.inner.write_path(request.sink);
                if state.notifying || state.notifications.is_empty() {
                    break state;
                }
                drop(state);
                self.resume_notifications();
            };
            let decision_at_ms = request.decision_clock.now_millis();
            let (values, journal) = guard.parts_mut();
            if journal
                .source
                .decision_time_floors
                .get(&request.claim.scope_epoch)
                .is_some_and(|floor| decision_at_ms < *floor)
            {
                return Err(aborted("Source decision clock regressed"));
            }
            let Some(record) = journal
                .source
                .installations
                .get(request.claim.installation_id)
            else {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::ScopeInactive,
                ));
            };
            if record.scope_epoch(request.claim.projection_id) != Some(request.claim.scope_epoch) {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::ScopeInactive,
                ));
            }
            let Some(source) = record
                .definition
                .projection(request.claim.projection_id)
                .and_then(|projection| projection.emits.as_ref())
            else {
                return Err(aborted("active Source scope has no declaration"));
            };
            if source.sink != *request.sink
                || source.capacity != *request.capacity
                || source.max_inline_payload_bytes != request.max_inline_payload_bytes
                || source.rate_limit.as_ref() != request.rate_limit
            {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::DeclarationMismatch,
                ));
            }
            if let (Some(stream), Some(key)) = (request.stream, stream_key.as_ref()) {
                match journal.source.sequences.get(key.as_slice()) {
                    None => {
                        return Ok(SourceCommitOutcome::Rejected(
                            SourceCommitRejection::StreamInactive,
                        ));
                    }
                    Some(active) if active.stream_epoch != stream.stream_epoch => {
                        return Ok(SourceCommitOutcome::Rejected(
                            SourceCommitRejection::StreamEpochMismatch {
                                active_epoch: active.stream_epoch,
                            },
                        ));
                    }
                    Some(_) => {}
                }
            }
            let previous_event = journal.source.events.get(event_key.as_slice());
            if let Some(record) = previous_event
                && decision_at_ms <= record.expires_at_ms
            {
                let accepted_stream = record
                    .stream
                    .as_ref()
                    .map(|stream| (stream.stream_id.as_str(), stream.seq));
                let attempted_stream = request.stream.map(|stream| (stream.stream_id, stream.seq));
                return Ok(
                    if record.payload_digest == payload_digest
                        && accepted_stream == attempted_stream
                    {
                        SourceCommitOutcome::Duplicate
                    } else {
                        SourceCommitOutcome::Rejected(SourceCommitRejection::EventIdConflict)
                    },
                );
            }
            let previous_claim = previous_event.map(|record| record.claim_id);
            if journal.source.receipts.contains_key(receipt_key.as_slice()) {
                return Err(aborted("Source claim identity already exists"));
            }
            if let (Some(stream), Some(key)) = (request.stream, stream_key.as_ref()) {
                let previous = journal
                    .source
                    .sequences
                    .get(key.as_slice())
                    .map(|state| state.last_seq);
                let expected = previous
                    .map_or(Some(1), |last| last.checked_add(1))
                    .ok_or_else(|| aborted("Source sequence exhausted"))?;
                if stream.seq < expected {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::SequenceReplay {
                            last: previous.unwrap_or(0),
                            seq: stream.seq,
                        },
                    ));
                }
                if stream.seq > expected {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::SequenceGap {
                            expected,
                            seq: stream.seq,
                        },
                    ));
                }
            }
            let rate_cutoff =
                if let (Some(rule), Some(key)) = (request.rate_limit, rate_key.as_ref()) {
                    if rule.window_ms == 0 || rule.max_events == 0 {
                        return Ok(SourceCommitOutcome::Rejected(
                            SourceCommitRejection::RateLimited,
                        ));
                    }
                    if usize::try_from(rule.max_events).map_or(true, |max| max > MAX_RATE_HITS) {
                        return Err(aborted("Source rate record exceeds maximum"));
                    }
                    let cutoff = cutoff(decision_at_ms, rule.window_ms);
                    let max_hits = usize::try_from(rule.max_events)
                        .map_err(|_error| aborted("Source rate limit exceeds address space"))?;
                    let retained = journal
                        .source
                        .rates
                        .get(key.as_slice())
                        .filter(|record| record.window_ms == rule.window_ms)
                        .map_or(0, |record| {
                            record
                                .hits
                                .iter()
                                .filter(|time| i128::from(**time) > cutoff)
                                .count()
                        });
                    if retained >= max_hits {
                        return Ok(SourceCommitOutcome::Rejected(
                            SourceCommitRejection::RateLimited,
                        ));
                    }
                    Some(cutoff)
                } else {
                    None
                };

            let current = values.get(request.sink);
            let count = match current
                .and_then(super::CurrentRecord::value)
                .map(Value::view)
            {
                None => 0,
                Some(ValueView::List(items)) => items.len(),
                Some(_) => {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::SinkTypeMismatch,
                    ));
                }
            };
            let replace = match &request.capacity.on_overflow {
                OverflowPolicy::DropOldest => count >= max_events,
                OverflowPolicy::Backpressure {
                    pause_threshold, ..
                } => {
                    let pause = usize::try_from(*pause_threshold).map_err(|_error| {
                        aborted("Source pause threshold exceeds address space")
                    })?;
                    if count >= pause || count >= max_events {
                        return Ok(SourceCommitOutcome::Rejected(
                            SourceCommitRejection::Backpressured,
                        ));
                    }
                    false
                }
                OverflowPolicy::DisconnectBridge => {
                    if count >= max_events {
                        return Ok(SourceCommitOutcome::Rejected(
                            SourceCommitRejection::CapacityExceeded,
                        ));
                    }
                    false
                }
            };
            let retained = journal
                .source
                .events
                .len()
                .checked_add(journal.source.rates.len())
                .ok_or_else(|| aborted("Source retention count overflow"))?;
            let added = usize::from(previous_claim.is_none())
                + usize::from(
                    rate_key
                        .as_ref()
                        .is_some_and(|key| !journal.source.rates.contains_key(key.as_slice())),
                );
            if added != 0
                && retained
                    .checked_add(added)
                    .is_none_or(|next| next > self.options.source_retention_limit.get())
            {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::RetentionCapacityExceeded,
                ));
            }
            let observed = current.map_or_else(
                || request.taint.clone(),
                |current| current.taint().clone().merged(request.taint),
            );
            let (stored, event) = if replace {
                let keep = max_events - 1;
                let removed = u64::try_from(count - keep)
                    .map_err(|_error| aborted("Source sink length exceeds supported range"))?;
                let stored = crate::values::drop_prefix_append_observed_value(
                    request.sink,
                    current.and_then(super::CurrentRecord::value),
                    removed,
                    request.payload.clone(),
                    observed,
                )
                .map_err(|_error| aborted("Source sink prefix drop failed"))?;
                let event = StateEvent::DropPrefixAppend {
                    path: request.sink.clone(),
                    removed,
                    item: request.payload.clone(),
                    taint: stored.taint.clone(),
                };
                (stored, event)
            } else {
                let stored = crate::values::append_observed_value(
                    request.sink,
                    current.and_then(super::CurrentRecord::value),
                    request.payload.clone(),
                    observed,
                )
                .map_err(|_error| aborted("Source sink append failed"))?;
                let event = StateEvent::Append {
                    path: request.sink.clone(),
                    item: request.payload.clone(),
                    taint: stored.taint.clone(),
                };
                (stored, event)
            };
            let at_millis = (self.options.history == MemoryHistory::Full
                && crate::history_retains_path(request.sink))
            .then(|| {
                journal
                    .last_history_millis
                    .checked_add(1)
                    .map(|next| next.max(now_millis()))
                    .ok_or_else(|| aborted("State history timestamp exhausted"))
            })
            .transpose()?;
            let targets = journal.subscribers.matching(request.sink);
            if !targets.is_empty()
                && journal.notifications.len() >= self.options.notification_capacity.get()
            {
                for notification in &mut journal.notifications {
                    notification
                        .targets
                        .retain(|target| target.receiver_count() != 0);
                }
                journal
                    .notifications
                    .retain(|notification| !notification.targets.is_empty());
                if journal.notifications.len() >= self.options.notification_capacity.get() {
                    return Err(aborted("State notification backlog exhausted"));
                }
            }
            let receipt = SourceReceipt {
                installation_id: request.claim.installation_id.to_owned(),
                projection_id: request.claim.projection_id.to_owned(),
                scope_epoch: request.claim.scope_epoch,
                stream_epoch: request.claim.stream_epoch,
                event_id: request.claim.event_id.to_owned(),
                claim_id: request.claim.claim_id,
                sink: request.sink.clone(),
                received_at_ms: request.received_at_ms,
            };
            if crate::host::encoded_size(&stored)
                .map_err(|_error| aborted("Source sink size could not be measured"))?
                > MAX_DECLARED_SINK_BYTES
            {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::CapacityExceeded,
                ));
            }
            if crate::host::encoded_size(&receipt)
                .map_err(|_error| aborted("Source receipt size could not be measured"))?
                > MAX_RECEIPT_BYTES
            {
                return Err(aborted("Source receipt row exceeds byte maximum"));
            }
            let old_receipt_key = previous_claim.map(|claim_id| {
                let mut key = Vec::with_capacity(event_key.len() + 16);
                key.push(b'C');
                key.extend_from_slice(&event_key[1..]);
                key.extend_from_slice(claim_id.as_bytes());
                key
            });
            let stored = super::CurrentRecord::Live(stored);
            let absence = journal
                .absence
                .replacing(current, Some(&stored), &self.options)
                .map_err(|_error| aborted("Source absence accounting failed"))?;
            journal
                .source
                .decision_time_floors
                .insert(request.claim.scope_epoch, decision_at_ms);
            let displaced = values.insert(request.sink.clone(), stored);
            journal.absence = absence;
            if let Some(old_receipt_key) = old_receipt_key {
                journal.source.receipts.remove(old_receipt_key.as_slice());
            }
            journal.source.events.insert(
                event_key,
                AcceptedEvent {
                    claim_id: request.claim.claim_id,
                    expires_at_ms: xolotl_source::event_expires_at(
                        decision_at_ms,
                        request.dedupe_window_ms,
                    ),
                    payload_digest,
                    stream: request.stream.map(|stream| AcceptedStream {
                        stream_id: stream.stream_id.to_owned(),
                        seq: stream.seq,
                    }),
                },
            );
            if let (Some(key), Some(stream)) = (stream_key, request.stream) {
                journal
                    .source
                    .sequences
                    .get_mut(key.as_slice())
                    .ok_or_else(|| aborted("active Source stream disappeared"))?
                    .last_seq = stream.seq;
            }
            if let (Some(key), Some(cutoff), Some(rule)) =
                (rate_key, rate_cutoff, request.rate_limit)
            {
                let record = journal
                    .source
                    .rates
                    .entry(key)
                    .or_insert_with(|| RateRecord {
                        window_ms: rule.window_ms,
                        hits: Vec::new(),
                    });
                if record.window_ms != rule.window_ms {
                    record.window_ms = rule.window_ms;
                    record.hits.clear();
                }
                record.hits.retain(|time| i128::from(*time) > cutoff);
                let position = record.hits.partition_point(|time| *time <= decision_at_ms);
                record.hits.insert(position, decision_at_ms);
            }
            journal.source.receipts.insert(receipt_key, receipt);
            if !targets.is_empty() {
                journal.notifications.push_back(Notification {
                    event: event.clone(),
                    targets,
                });
            }
            if let Some(at_millis) = at_millis {
                journal.last_history_millis = at_millis;
                journal
                    .history
                    .push_back(crate::StateHistoryEntry { at_millis, event });
            }
            let drain = !journal.notifying && !journal.notifications.is_empty();
            journal.notifying |= drain;
            (drain, displaced)
        };
        drop(displaced);
        if drain {
            self.drain_notifications();
        }
        Ok(SourceCommitOutcome::Accepted)
    }
}

impl SourceEventCommit for InMemoryBackend {
    fn commit<'a>(&'a self, request: SourceCommit<'a>) -> SourceFuture<'a, SourceCommitOutcome> {
        Box::pin(async move { self.commit_source(request) })
    }
}

impl SourceStreamLifecycle for InMemoryBackend {
    fn inspect_stream<'a>(
        &'a self,
        stream: SourceStreamScope<'a>,
    ) -> SourceFuture<'a, Option<SourceStreamSnapshot>> {
        Box::pin(async move {
            let key = stream_scope_key(stream, b'S')?;
            let revision_key = stream_scope_key(stream, b'V')?;
            let journal = self.inner.read();
            if !active_stream_scope(&journal.source, stream) {
                return Ok(None);
            }
            Ok(Some(SourceStreamSnapshot {
                revision: journal
                    .source
                    .stream_revisions
                    .get(revision_key.as_slice())
                    .copied()
                    .unwrap_or(0),
                active: journal.source.sequences.get(key.as_slice()).cloned(),
            }))
        })
    }

    fn open_stream<'a>(
        &'a self,
        request: SourceStreamOpen<'a>,
    ) -> SourceFuture<'a, SourceStreamOpenOutcome> {
        Box::pin(async move {
            let key = stream_scope_key(request.stream, b'S')?;
            let revision_key = stream_scope_key(request.stream, b'V')?;
            if request.open_id.is_empty() || request.open_id.len() > MAX_ID_BYTES {
                return Err(aborted("Source stream open identity is invalid"));
            }
            let mut journal = self.inner.write();
            if !active_stream_scope(&journal.source, request.stream) {
                return Ok(SourceStreamOpenOutcome::ScopeInactive);
            }
            let revision = journal
                .source
                .stream_revisions
                .get(revision_key.as_slice())
                .copied()
                .unwrap_or(0);
            if let Some(active) = journal.source.sequences.get(key.as_slice()) {
                let snapshot = SourceStreamSnapshot {
                    revision,
                    active: Some(active.clone()),
                };
                return Ok(
                    if active.open_id == request.open_id
                        && active.opened_at_revision == request.expected_revision
                    {
                        SourceStreamOpenOutcome::Opened(snapshot)
                    } else {
                        SourceStreamOpenOutcome::AlreadyOpen(snapshot)
                    },
                );
            }
            if request.expected_revision != revision {
                return Ok(SourceStreamOpenOutcome::RevisionConflict {
                    current_revision: revision,
                });
            }
            if journal.source.sequences.len() >= self.options.source_stream_limit.get() {
                return Ok(SourceStreamOpenOutcome::QuotaExceeded);
            }
            let next_epoch = journal
                .source
                .next_authority_epoch
                .checked_add(1)
                .ok_or_else(|| aborted("Source stream epoch exhausted"))?;
            let next_revision = revision
                .checked_add(1)
                .ok_or_else(|| aborted("Source stream revision exhausted"))?;
            let active = SourceStreamState {
                stream_epoch: next_epoch,
                opened_at_revision: revision,
                last_seq: 0,
                open_id: request.open_id.to_owned(),
            };
            journal.source.next_authority_epoch = next_epoch;
            journal
                .source
                .stream_revisions
                .insert(revision_key, next_revision);
            journal.source.sequences.insert(key, active.clone());
            Ok(SourceStreamOpenOutcome::Opened(SourceStreamSnapshot {
                revision: next_revision,
                active: Some(active),
            }))
        })
    }

    fn retire_stream<'a>(
        &'a self,
        request: SourceStreamRetire<'a>,
    ) -> SourceFuture<'a, SourceStreamRetireOutcome> {
        Box::pin(async move {
            let key = stream_scope_key(request.stream, b'S')?;
            let revision_key = stream_scope_key(request.stream, b'V')?;
            if request.stream_epoch == 0 {
                return Err(aborted("Source stream epoch is invalid"));
            }
            let mut journal = self.inner.write();
            if !active_stream_scope(&journal.source, request.stream) {
                return Ok(SourceStreamRetireOutcome::ScopeInactive);
            }
            let revision = journal
                .source
                .stream_revisions
                .get(revision_key.as_slice())
                .copied()
                .unwrap_or(0);
            let Some(active) = journal.source.sequences.get(key.as_slice()) else {
                return Ok(SourceStreamRetireOutcome::Inactive { revision });
            };
            if active.stream_epoch != request.stream_epoch {
                return Ok(SourceStreamRetireOutcome::Stale {
                    active_epoch: active.stream_epoch,
                });
            }
            let next_revision = revision
                .checked_add(1)
                .ok_or_else(|| aborted("Source stream revision exhausted"))?;
            journal.source.sequences.remove(key.as_slice());
            journal
                .source
                .stream_revisions
                .insert(revision_key, next_revision);
            Ok(SourceStreamRetireOutcome::Retired {
                revision: next_revision,
            })
        })
    }
}

impl SourceDeclarationAdmission for InMemoryBackend {
    fn validate_source(
        &self,
        installation_id: &str,
        projection_id: &str,
        source: &EventSource,
    ) -> Result<(), SourceAdmissionError> {
        xolotl_source::validate_builtin_source(installation_id, projection_id, source)
    }
}

impl ExternalInstallationAuthority for InMemoryBackend {
    fn load_installation<'a>(
        &'a self,
        id: &'a str,
    ) -> SourceFuture<'a, Option<ExternalInstallationRecord>> {
        Box::pin(async move { Ok(self.inner.read().source.installations.get(id).cloned()) })
    }

    fn list_installations<'a>(
        &'a self,
        after_id: Option<&'a str>,
        limit: std::num::NonZeroUsize,
    ) -> SourceFuture<'a, Vec<ExternalInstallationRecord>> {
        Box::pin(async move {
            let journal = self.inner.read();
            let rows = &journal.source.installations;
            Ok(match after_id {
                Some(after) => rows
                    .range(after.to_owned()..)
                    .filter(|(id, _)| id.as_str() > after)
                    .take(limit.get())
                    .map(|(_, record)| record.clone())
                    .collect(),
                None => rows.values().take(limit.get()).cloned().collect(),
            })
        })
    }

    fn compare_install<'a>(
        &'a self,
        mut definition: ExternalInstallationDef,
        expected: Option<ExternalInstallationRevision>,
    ) -> SourceFuture<'a, ExternalInstallationMutation> {
        Box::pin(async move {
            definition
                .validate_admission()
                .map_err(|error| aborted(format!("installation admission failed: {error}")))?;
            for projection in &definition.projections {
                if let Some(source) = projection.emits.as_ref() {
                    self.validate_source(&definition.id, &projection.id, source)
                        .map_err(|error| aborted(error.to_string()))?;
                }
            }
            let mut journal = self.inner.write();
            let current = journal
                .source
                .installations
                .get(&definition.id)
                .map(ExternalInstallationRecord::revision);
            if current != expected {
                return Ok(ExternalInstallationMutation::Conflict { current });
            }
            definition.version = expected
                .map_or(0, |revision| revision.version)
                .checked_add(1)
                .ok_or_else(|| aborted("installation version exhausted"))?;
            let source_count = definition
                .projections
                .iter()
                .filter(|projection| projection.emits.is_some())
                .count();
            let new_installation = current.is_none();
            let allocated = u64::try_from(source_count)
                .ok()
                .and_then(|count| count.checked_add(u64::from(new_installation)))
                .ok_or_else(|| aborted("installation epoch range exhausted"))?;
            let high = journal
                .source
                .next_authority_epoch
                .checked_add(allocated)
                .ok_or_else(|| aborted("installation epoch exhausted"))?;
            let installation_epoch = if new_installation {
                journal.source.next_authority_epoch + 1
            } else {
                journal
                    .source
                    .installations
                    .get(&definition.id)
                    .ok_or_else(|| aborted("installation record missing"))?
                    .installation_epoch
            };
            let mut next_epoch = installation_epoch;
            if !new_installation {
                next_epoch = journal.source.next_authority_epoch;
            }
            let mut scope_epochs = BTreeMap::new();
            for projection in &definition.projections {
                if projection.emits.is_some() {
                    next_epoch += 1;
                    scope_epochs.insert(projection.id.clone(), next_epoch);
                }
            }
            let record = ExternalInstallationRecord {
                definition,
                installation_epoch,
                scope_epochs,
            };
            // Count the same JSON representation redb stores, without
            // allocating a second copy of the declaration. Reject before
            // changing the catalog or consuming an authority epoch.
            if crate::host::encoded_size(&record)
                .map_err(|error| aborted(format!("installation encoding failed: {error}")))?
                > MAX_INSTALLATION_RECORD_BYTES
            {
                return Err(aborted("external installation record exceeds byte maximum"));
            }
            let displaced_revision_keys = journal
                .source
                .installations
                .get(&record.definition.id)
                .map(|old| {
                    old.scope_epochs
                        .iter()
                        .map(|(projection, epoch)| {
                            revision_key(&old.definition.id, projection, *epoch)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            journal.source.next_authority_epoch = high;
            let displaced = journal
                .source
                .installations
                .insert(record.definition.id.clone(), record.clone());
            for key in displaced_revision_keys {
                journal.source.stream_revisions.remove(key.as_slice());
            }
            if let Some(old) = &displaced {
                for epoch in old.scope_epochs.values() {
                    journal.source.decision_time_floors.remove(epoch);
                }
            }
            drop(journal);
            drop(displaced);
            Ok(ExternalInstallationMutation::Applied(Some(record)))
        })
    }

    fn compare_retire<'a>(
        &'a self,
        id: &'a str,
        expected: ExternalInstallationRevision,
    ) -> SourceFuture<'a, ExternalInstallationMutation> {
        Box::pin(async move {
            let mut journal = self.inner.write();
            let current = journal
                .source
                .installations
                .get(id)
                .map(ExternalInstallationRecord::revision);
            if current != Some(expected) {
                return Ok(ExternalInstallationMutation::Conflict { current });
            }
            let retired_revision_keys = journal
                .source
                .installations
                .get(id)
                .ok_or_else(|| aborted("installation record missing"))?
                .scope_epochs
                .iter()
                .map(|(projection, epoch)| revision_key(id, projection, *epoch))
                .collect::<Result<Vec<_>, _>>()?;
            let displaced = journal.source.installations.remove(id);
            for key in retired_revision_keys {
                journal.source.stream_revisions.remove(key.as_slice());
            }
            if let Some(old) = &displaced {
                for epoch in old.scope_epochs.values() {
                    journal.source.decision_time_floors.remove(epoch);
                }
            }
            drop(journal);
            drop(displaced);
            Ok(ExternalInstallationMutation::Applied(None))
        })
    }
}

impl SourceClaimInspection for InMemoryBackend {
    fn inspect<'a>(
        &'a self,
        request: SourceEvidenceInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence> {
        Box::pin(async move {
            let key = claim_key(request.claim)?;
            let journal = self.inner.read();
            if journal
                .source
                .receipts
                .get(key.as_slice())
                .is_some_and(|receipt| {
                    receipt.installation_id != request.claim.installation_id
                        || receipt.projection_id != request.claim.projection_id
                        || receipt.scope_epoch != request.claim.scope_epoch
                        || receipt.stream_epoch != request.claim.stream_epoch
                        || receipt.event_id != request.claim.event_id
                        || receipt.claim_id != request.claim.claim_id
                })
            {
                return Err(aborted("Source receipt identity does not match its key"));
            }
            let evidence = journal.source.receipts.get(key.as_slice()).cloned().map_or(
                SourceClaimEvidence::Unproven,
                SourceClaimEvidence::Committed,
            );
            Ok(evidence)
        })
    }

    fn inspect_event<'a>(
        &'a self,
        request: SourceEventDecisionInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence> {
        Box::pin(async move {
            let event_key = event_key_for(
                request.installation_id,
                request.projection_id,
                request.scope_epoch,
                request.stream_epoch,
                request.event_id,
            )?;
            let journal = self.inner.read();
            let claim_id = journal
                .source
                .events
                .get(event_key.as_slice())
                .map(|accepted| accepted.claim_id);
            let receipt = if let Some(claim_id) = claim_id {
                let claim = xolotl_source::SourceClaim {
                    installation_id: request.installation_id,
                    projection_id: request.projection_id,
                    scope_epoch: request.scope_epoch,
                    stream_epoch: request.stream_epoch,
                    event_id: request.event_id,
                    claim_id,
                };
                let key = claim_key(claim)?;
                let receipt = journal
                    .source
                    .receipts
                    .get(key.as_slice())
                    .cloned()
                    .ok_or_else(|| aborted("retained Source event has no claim receipt"))?;
                if receipt.installation_id != request.installation_id
                    || receipt.projection_id != request.projection_id
                    || receipt.scope_epoch != request.scope_epoch
                    || receipt.stream_epoch != request.stream_epoch
                    || receipt.event_id != request.event_id
                    || receipt.claim_id != claim_id
                {
                    return Err(aborted(
                        "Source receipt identity does not match event decision",
                    ));
                }
                Some(receipt)
            } else {
                None
            };
            Ok(receipt.map_or(
                SourceClaimEvidence::Unproven,
                SourceClaimEvidence::Committed,
            ))
        })
    }
}

impl SourceEventMaintenance for InMemoryBackend {
    fn maintain<'a>(
        &'a self,
        request: SourceMaintenance,
    ) -> SourceFuture<'a, SourceMaintenanceResult> {
        Box::pin(async move {
            if request.limit.get() > MAX_MAINTENANCE_BATCH {
                return Err(aborted("Source maintenance batch exceeds maximum"));
            }
            let mut journal = self.inner.write();
            let decision_at_ms = request.decision_clock.now_millis();
            let prior = journal.source.cursor.clone();
            let start = prior.as_deref().unwrap_or(b"E");
            let mut candidates = Vec::with_capacity(request.limit.get());
            let mut has_more = false;
            let events = journal
                .source
                .events
                .range(start.to_vec()..)
                .map(|(key, _)| key);
            let rates = journal
                .source
                .rates
                .range(start.to_vec()..)
                .map(|(key, _)| key);
            let streams = journal
                .source
                .sequences
                .range(start.to_vec()..)
                .map(|(key, _)| key);
            for key in events.chain(rates).chain(streams) {
                if prior.as_ref().is_some_and(|prior| key <= prior) {
                    continue;
                }
                if candidates.len() == request.limit.get() {
                    has_more = true;
                    break;
                }
                candidates.push(key.clone());
            }
            let mut result = SourceMaintenanceResult {
                examined: candidates.len(),
                removed: 0,
                reached_end: !has_more,
            };
            let mut floors = BTreeMap::new();
            for key in &candidates {
                let (installation, projection, epoch) = parse_source_scope(key)?;
                let active = journal
                    .source
                    .installations
                    .get(installation)
                    .and_then(|record| record.scope_epoch(projection));
                if active == Some(epoch) {
                    if journal
                        .source
                        .decision_time_floors
                        .get(&epoch)
                        .is_some_and(|floor| decision_at_ms < *floor)
                    {
                        return Err(aborted("Source decision clock regressed"));
                    }
                    floors.insert(epoch, decision_at_ms);
                }
            }
            journal.source.decision_time_floors.extend(floors);
            for key in &candidates {
                match key.first() {
                    Some(b'E') => {
                        let Some(record) = journal.source.events.get(key) else {
                            continue;
                        };
                        if decision_at_ms <= record.expires_at_ms {
                            continue;
                        }
                        let mut receipt_key = Vec::with_capacity(key.len() + 16);
                        receipt_key.push(b'C');
                        receipt_key.extend_from_slice(&key[1..]);
                        receipt_key.extend_from_slice(record.claim_id.as_bytes());
                        journal.source.events.remove(key);
                        journal.source.receipts.remove(receipt_key.as_slice());
                        result.removed += 1;
                    }
                    Some(b'R') => {
                        let Some(record) = journal.source.rates.get(key) else {
                            continue;
                        };
                        let expired = record.hits.last().is_none_or(|last| {
                            i128::from(decision_at_ms)
                                >= i128::from(*last) + i128::from(record.window_ms)
                        });
                        if expired {
                            journal.source.rates.remove(key);
                            result.removed += 1;
                        }
                    }
                    Some(b'S') => {
                        let (installation, projection, epoch) = parse_source_scope(key)?;
                        let active = journal
                            .source
                            .installations
                            .get(installation)
                            .and_then(|record| record.scope_epoch(projection));
                        if active != Some(epoch) {
                            journal.source.sequences.remove(key);
                            result.removed += 1;
                        }
                    }
                    _ => return Err(aborted("Source maintenance key is invalid")),
                }
            }
            if has_more {
                if let Some(last) = candidates.last() {
                    journal.source.cursor = Some(last.clone());
                }
            } else {
                journal.source.cursor = None;
            }
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StateHistory, StateHistoryQuery, StateRead, StateWatch, StateWriteExt};
    use anyhow::ensure;
    use std::num::NonZeroUsize;
    use xolotl_source::{SourceClaim, SourceClaimId, SourceStreamPosition};
    use xolotl_types::{
        Path, Purity, TaintSet, TaintSource, Transport, TrustLevel,
        external::{EventSource, ExternalProjectionDef, Role, SourceRateLimit, StreamCapacity},
    };

    async fn install_source(
        backend: &InMemoryBackend,
        installation_id: &str,
        projection_id: &str,
        sink: &Path,
        capacity: &StreamCapacity,
        max_inline_payload_bytes: usize,
        rate_limit: Option<&SourceRateLimit>,
    ) -> anyhow::Result<u64> {
        let definition = ExternalInstallationDef {
            id: installation_id.into(),
            platform: "test".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Full,
            config_schema: Value::map(Default::default()),
            config: Value::null(),
            projections: vec![ExternalProjectionDef {
                id: projection_id.into(),
                role: Role::Source,
                namespace: None,
                provides: vec![],
                emits: Some(EventSource {
                    sink: sink.clone(),
                    purity: Purity::Effectful,
                    event_schema: None,
                    max_inline_payload_bytes,
                    capacity: capacity.clone(),
                    rate_limit: rate_limit.cloned(),
                    commands: false,
                    command_schema: None,
                    command_result_schema: None,
                }),
                version: 1,
            }],
            version: 0,
        };
        let ExternalInstallationMutation::Applied(Some(record)) =
            backend.compare_install(definition, None).await?
        else {
            anyhow::bail!("Source test installation was not applied")
        };
        record
            .scope_epoch(projection_id)
            .ok_or_else(|| anyhow::anyhow!("installed Source projection has no scope epoch"))
    }

    async fn open_stream_for_test(
        backend: &InMemoryBackend,
        installation_id: &str,
        projection_id: &str,
        scope_epoch: u64,
        stream_id: &str,
    ) -> anyhow::Result<u64> {
        let stream = SourceStreamScope {
            installation_id,
            projection_id,
            scope_epoch,
            stream_id,
        };
        let Some(snapshot) = backend.inspect_stream(stream).await? else {
            anyhow::bail!("test Source scope is inactive");
        };
        let SourceStreamOpenOutcome::Opened(snapshot) = backend
            .open_stream(SourceStreamOpen {
                stream,
                open_id: "test-open",
                expected_revision: snapshot.revision,
            })
            .await?
        else {
            anyhow::bail!("test Source stream did not open");
        };
        snapshot
            .active
            .map(|state| state.stream_epoch)
            .ok_or_else(|| anyhow::anyhow!("opened stream has no state"))
    }

    #[tokio::test]
    async fn source_reconstruction_preserves_absence_and_releases_its_charge() -> anyhow::Result<()>
    {
        for history in [MemoryHistory::Disabled, MemoryHistory::Full] {
            for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(6)] {
                let backend = InMemoryBackend::with_options(super::super::InMemoryOptions {
                    history,
                    read_shards,
                    absence_limits: crate::AbsenceLimits {
                        records: Some(1),
                        ..Default::default()
                    },
                    ..Default::default()
                })?;
                let sink = Path::parse("state://events/external/test/absence")?;
                let capacity = StreamCapacity {
                    max_events: 2,
                    on_overflow: OverflowPolicy::DropOldest,
                };
                let epoch =
                    install_source(&backend, "test", "absence", &sink, &capacity, 1024, None)
                        .await?;
                let previous = TaintSet::of(TaintSource::ModelOutput);
                let control = TaintSet::author();
                backend
                    .write_set_tainted(&sink, Value::list(vec![]), previous.clone())
                    .await?;
                backend.write_delete_tainted(&sink, control.clone()).await?;
                let absent = backend.read_at(&sink, 0).await?;
                ensure!(absent.value.is_none() && absent.taint == previous.merged(&control));
                ensure!(backend.inner.read().absence.records == 1);
                let taint = TaintSet::of(TaintSource::Fetched {
                    host: "source".into(),
                });
                let payload = Value::integer(4);
                let request = || SourceCommit {
                    claim: SourceClaim {
                        installation_id: "test",
                        projection_id: "absence",
                        scope_epoch: epoch,
                        stream_epoch: None,
                        event_id: "rebuild",
                        claim_id: SourceClaimId::from_bytes([6; 16]),
                    },
                    received_at_ms: 100,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 100;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 1000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1024,
                    payload: &payload,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                };
                let mut watcher = backend.subscribe(&sink).await?;
                let oversized = Value::string("x".repeat(1025));
                let mut rejected = request();
                rejected.payload = &oversized;
                let usage = backend.inner.read().absence;
                let history_len = backend.inner.read().history.len();
                ensure!(
                    SourceEventCommit::commit(&backend, rejected).await?
                        == SourceCommitOutcome::Rejected(SourceCommitRejection::PayloadTooLarge)
                );
                ensure!(backend.read_at(&sink, 0).await? == absent);
                ensure!(backend.inner.read().absence == usage);
                ensure!(backend.inner.read().history.len() == history_len);
                ensure!(backend.inner.read().source.events.is_empty());
                ensure!(backend.inner.read().source.receipts.is_empty());
                ensure!(matches!(
                    watcher.try_recv(),
                    Err(crate::StateWatchError::Empty)
                ));
                ensure!(
                    SourceEventCommit::commit(&backend, request()).await?
                        == SourceCommitOutcome::Accepted
                );
                let current = backend.read_at(&sink, 0).await?;
                ensure!(current.value == Some(Value::list(vec![payload.clone()])));
                ensure!(current.taint == absent.taint.merged(&taint));
                ensure!(backend.inner.read().absence == super::super::AbsenceUsage::default());
                ensure!(
                    matches!(watcher.try_recv()?, StateEvent::Append { taint: observed, .. }
                    if observed == current.taint)
                );
                let history_len = backend.inner.read().history.len();
                ensure!(
                    SourceEventCommit::commit(&backend, request()).await?
                        == SourceCommitOutcome::Duplicate
                );
                ensure!(backend.read_at(&sink, 0).await? == current);
                ensure!(backend.inner.read().history.len() == history_len);
                ensure!(backend.inner.read().absence == super::super::AbsenceUsage::default());
                ensure!(matches!(
                    watcher.try_recv(),
                    Err(crate::StateWatchError::Empty)
                ));
                let journal = backend.inner.read();
                ensure!(journal.source.events.len() == 1 && journal.source.receipts.len() == 1);
                if history == MemoryHistory::Full {
                    let mut reconstructed = crate::StateObservation::default();
                    for entry in &journal.history {
                        crate::apply_history_event(&mut reconstructed, &entry.event)?;
                    }
                    ensure!(reconstructed == current);
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn drop_oldest_publishes_replayable_delta_after_ordinary_state_write()
    -> anyhow::Result<()> {
        let backend = InMemoryBackend::with_options(super::super::InMemoryOptions {
            history: MemoryHistory::Full,
            ..Default::default()
        })?;
        let sink = Path::parse("state://events/external/test/source")?;
        let capacity = StreamCapacity {
            max_events: 2,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let epoch =
            install_source(&backend, "test", "source", &sink, &capacity, 1024, None).await?;
        let prior_taint = TaintSet::of(TaintSource::ModelOutput);
        backend
            .write_set_tainted(
                &sink,
                Value::list((0..4).map(Value::integer).collect()),
                prior_taint.clone(),
            )
            .await?;
        let mut watcher = backend.subscribe(&sink).await?;
        let payload = Value::integer(4);
        let taint = TaintSet::author();
        let combined = prior_taint.merged(&taint);
        ensure!(
            SourceEventCommit::commit(
                &backend,
                SourceCommit {
                    claim: SourceClaim {
                        installation_id: "test",
                        projection_id: "source",
                        scope_epoch: epoch,
                        stream_epoch: None,
                        event_id: "window",
                        claim_id: SourceClaimId::from_bytes([4; 16]),
                    },
                    received_at_ms: 100,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 100;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 1000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1024,
                    payload: &payload,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                },
            )
            .await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(matches!(
            watcher.try_recv()?,
            StateEvent::DropPrefixAppend { removed: 3, item, taint: observed, .. }
                if item == payload && observed == combined
        ));
        let current = backend.read_tainted(&sink).await?;
        ensure!(current.value.as_ref() == Some(&Value::list(vec![Value::integer(3), payload])));
        ensure!(current.taint == combined);
        let history = backend
            .history(&StateHistoryQuery::new(sink, 0, i64::MAX))
            .await?;
        ensure!(history.entries.len() == 2);
        let mut replay = crate::StateObservation::default();
        for entry in &history.entries {
            crate::apply_history_event(&mut replay, &entry.event)?;
        }
        ensure!(replay == current);
        Ok(())
    }

    #[test]
    fn declaration_admission_uses_builtin_source_bounds() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let mut source = EventSource {
            sink: Path::parse("state://events/external/installation/source")?,
            purity: Purity::Effectful,
            event_schema: None,
            max_inline_payload_bytes: 1024,
            capacity: StreamCapacity {
                max_events: 4,
                on_overflow: OverflowPolicy::DropOldest,
            },
            rate_limit: Some(SourceRateLimit {
                window_ms: 1000,
                max_events: 4,
            }),
            commands: false,
            command_schema: None,
            command_result_schema: None,
        };
        ensure!(
            backend
                .validate_source("installation", "source", &source)
                .is_ok()
        );
        source.rate_limit = Some(SourceRateLimit {
            window_ms: 1000,
            max_events: (xolotl_source::MAX_RATE_HITS + 1) as u32,
        });
        ensure!(
            backend.validate_source("installation", "source", &source)
                == Err(SourceAdmissionError::LimitExceeded {
                    field: "rate hits",
                    max: xolotl_source::MAX_RATE_HITS,
                })
        );
        Ok(())
    }

    #[tokio::test]
    async fn maximum_legal_receipt_encoding_can_commit_and_be_inspected() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let mut sink_text = String::from("state://");
        sink_text.push_str(&"x".repeat(xolotl_source::MAX_SINK_PATH_BYTES - sink_text.len()));
        let sink = Path::parse(&sink_text)?;
        let id = "x".repeat(MAX_ID_BYTES);
        let capacity = StreamCapacity {
            max_events: 1,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::null();
        let taint = TaintSet::pristine();
        let scope_epoch = install_source(&backend, &id, &id, &sink, &capacity, 1024, None).await?;
        let claim = SourceClaim {
            installation_id: &id,
            projection_id: &id,
            scope_epoch,
            stream_epoch: None,
            event_id: &id,
            claim_id: SourceClaimId::from_bytes([u8::MAX; 16]),
        };
        ensure!(
            SourceEventCommit::commit(
                &backend,
                SourceCommit {
                    claim,
                    received_at_ms: i64::MIN,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = i64::MIN;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 1,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1024,
                    payload: &payload,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                },
            )
            .await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(matches!(
            backend
                .inspect(SourceEvidenceInspection {
                    claim,
                })
                .await?,
            SourceClaimEvidence::Committed(receipt) if receipt.sink == sink
        ));
        Ok(())
    }

    #[tokio::test]
    async fn encoded_sink_limit_rejects_without_reserving_source_state() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let sink = Path::parse("state://events/external/installation/source")?;
        let capacity = StreamCapacity {
            max_events: 64,
            on_overflow: OverflowPolicy::DropOldest,
        };
        ensure!(
            capacity.max_events as usize * xolotl_source::MAX_INLINE_PAYLOAD_BYTES
                == MAX_DECLARED_SINK_BYTES
        );
        let rate = SourceRateLimit {
            window_ms: 1000,
            max_events: 1,
        };
        let payload = Value::null();
        let oversized_taint = TaintSet::of(TaintSource::Fetched {
            host: "x".repeat(MAX_DECLARED_SINK_BYTES).into(),
        });
        let claim = SourceClaim {
            installation_id: "installation",
            projection_id: "source",
            scope_epoch: install_source(
                &backend,
                "installation",
                "source",
                &sink,
                &capacity,
                xolotl_source::MAX_INLINE_PAYLOAD_BYTES,
                Some(&rate),
            )
            .await?,
            stream_epoch: None,
            event_id: "byte-budget",
            claim_id: SourceClaimId::from_bytes([1; 16]),
        };
        let stream_epoch = open_stream_for_test(
            &backend,
            claim.installation_id,
            claim.projection_id,
            claim.scope_epoch,
            "ordered",
        )
        .await?;
        let claim = SourceClaim {
            stream_epoch: Some(stream_epoch),
            ..claim
        };
        ensure!(
            SourceEventCommit::commit(
                &backend,
                SourceCommit {
                    claim,
                    received_at_ms: 100,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 100;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 1000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: xolotl_source::MAX_INLINE_PAYLOAD_BYTES,
                    payload: &payload,
                    taint: &oversized_taint,
                    stream: Some(SourceStreamPosition {
                        stream_id: "ordered",
                        stream_epoch,
                        seq: 1,
                    }),
                    rate_limit: Some(&rate),
                },
            )
            .await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::CapacityExceeded)
        );
        {
            let journal = backend.inner.read();
            ensure!(journal.source.events.is_empty());
            ensure!(
                journal
                    .source
                    .sequences
                    .values()
                    .all(|state| state.last_seq == 0)
            );
            ensure!(journal.source.rates.is_empty());
            ensure!(journal.source.receipts.is_empty());
        }
        ensure!(backend.inner.observe(&sink).value.is_none());

        let pristine = TaintSet::pristine();
        ensure!(
            SourceEventCommit::commit(
                &backend,
                SourceCommit {
                    claim: SourceClaim {
                        claim_id: SourceClaimId::from_bytes([2; 16]),
                        ..claim
                    },
                    received_at_ms: 101,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 101;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 1000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: xolotl_source::MAX_INLINE_PAYLOAD_BYTES,
                    payload: &payload,
                    taint: &pristine,
                    stream: Some(SourceStreamPosition {
                        stream_id: "ordered",
                        stream_epoch,
                        seq: 1,
                    }),
                    rate_limit: Some(&rate),
                },
            )
            .await?
                == SourceCommitOutcome::Accepted
        );
        Ok(())
    }

    #[tokio::test]
    async fn non_sequence_sink_rejects_without_reserving_source_state() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let sink = Path::parse("state://events/external/installation/source")?;
        let capacity = StreamCapacity {
            max_events: 1,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let rate = SourceRateLimit {
            window_ms: 1000,
            max_events: 1,
        };
        let payload = Value::string("event".into());
        let taint = TaintSet::pristine();
        let scope_epoch = install_source(
            &backend,
            "installation",
            "source",
            &sink,
            &capacity,
            1024,
            Some(&rate),
        )
        .await?;
        let stream_epoch =
            open_stream_for_test(&backend, "installation", "source", scope_epoch, "stream").await?;
        backend.write_set(&sink, Value::integer(7)).await?;
        let request = |claim_id| SourceCommit {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch,
                stream_epoch: Some(stream_epoch),
                event_id: "event",
                claim_id: SourceClaimId::from_bytes([claim_id; 16]),
            },
            received_at_ms: 100,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = 100;
                move || decision_at_ms
            }),
            dedupe_window_ms: 1000,
            sink: &sink,
            capacity: &capacity,
            max_inline_payload_bytes: 1024,
            payload: &payload,
            taint: &taint,
            stream: Some(SourceStreamPosition {
                stream_id: "stream",
                stream_epoch,
                seq: 1,
            }),
            rate_limit: Some(&rate),
        };
        ensure!(
            SourceEventCommit::commit(&backend, request(1)).await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::SinkTypeMismatch)
        );
        ensure!(
            backend
                .inner
                .observe(&sink)
                .value
                .is_some_and(|stored| stored == Value::integer(7))
        );
        {
            let journal = backend.inner.read();
            ensure!(journal.source.events.is_empty());
            ensure!(
                journal
                    .source
                    .sequences
                    .values()
                    .all(|state| state.last_seq == 0)
            );
            ensure!(journal.source.rates.is_empty());
            ensure!(journal.source.receipts.is_empty());
        }
        backend.write_set(&sink, Value::list(Vec::new())).await?;
        ensure!(
            SourceEventCommit::commit(&backend, request(2)).await? == SourceCommitOutcome::Accepted
        );
        ensure!(
            backend
                .inner
                .observe(&sink)
                .value
                .is_some_and(|stored| stored.as_list().is_some_and(|items| items.len() == 1))
        );
        Ok(())
    }

    #[tokio::test]
    async fn accepted_event_expiry_is_fixed_when_window_changes() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let sink = Path::parse("state://events/external/test/source")?;
        let capacity = StreamCapacity {
            max_events: 4,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::string("event".into());
        let taint = TaintSet::pristine();
        let scope_epoch =
            install_source(&backend, "test", "source", &sink, &capacity, 1024, None).await?;
        let request = |claim_id, received_at_ms, dedupe_window_ms| SourceCommit {
            claim: SourceClaim {
                installation_id: "test",
                projection_id: "source",
                scope_epoch,
                stream_epoch: None,
                event_id: "fixed",
                claim_id: SourceClaimId::from_bytes([claim_id; 16]),
            },
            received_at_ms,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = received_at_ms;
                move || decision_at_ms
            }),
            dedupe_window_ms,
            sink: &sink,
            capacity: &capacity,
            max_inline_payload_bytes: 1024,
            payload: &payload,
            taint: &taint,
            stream: None,
            rate_limit: None,
        };
        ensure!(
            SourceEventCommit::commit(&backend, request(1, 100, 1000)).await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(
            SourceEventCommit::commit(&backend, request(2, 500, 1)).await?
                == SourceCommitOutcome::Duplicate
        );
        ensure!(
            backend
                .maintain(SourceMaintenance {
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 1100;
                        move || decision_at_ms
                    }),
                    limit: std::num::NonZeroUsize::MIN,
                })
                .await?
                .removed
                == 0
        );
        ensure!(
            backend
                .maintain(SourceMaintenance {
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 1101;
                        move || decision_at_ms
                    }),
                    limit: std::num::NonZeroUsize::MIN,
                })
                .await?
                .removed
                == 1
        );
        ensure!(
            SourceEventCommit::commit(&backend, request(3, 1102, 5000)).await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(
            SourceEventCommit::commit(&backend, request(4, 1200, 1)).await?
                == SourceCommitOutcome::Duplicate
        );
        Ok(())
    }

    #[tokio::test]
    async fn maintenance_reclaims_idle_rate_but_preserves_active_window_and_stream_position()
    -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let sink = Path::parse("state://events/external/test/source")?;
        let capacity = StreamCapacity {
            max_events: 4,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let rate = SourceRateLimit {
            window_ms: 1000,
            max_events: 1,
        };
        let payload = Value::string("event".into());
        let taint = TaintSet::pristine();
        let scope_epoch = install_source(
            &backend,
            "test",
            "source",
            &sink,
            &capacity,
            1024,
            Some(&rate),
        )
        .await?;
        let stream_epoch =
            open_stream_for_test(&backend, "test", "source", scope_epoch, "ordered").await?;
        let request = |claim_id, received_at_ms, seq| SourceCommit {
            claim: SourceClaim {
                installation_id: "test",
                projection_id: "source",
                scope_epoch,
                stream_epoch: Some(stream_epoch),
                event_id: match claim_id {
                    1 => "one",
                    2 => "two",
                    3 => "three",
                    _ => "four",
                },
                claim_id: SourceClaimId::from_bytes([claim_id; 16]),
            },
            received_at_ms,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = received_at_ms;
                move || decision_at_ms
            }),
            dedupe_window_ms: 1000,
            sink: &sink,
            capacity: &capacity,
            max_inline_payload_bytes: 1024,
            payload: &payload,
            taint: &taint,
            stream: Some(SourceStreamPosition {
                stream_id: "ordered",
                stream_epoch,
                seq,
            }),
            rate_limit: Some(&rate),
        };
        ensure!(
            SourceEventCommit::commit(&backend, request(1, 100, 1)).await?
                == SourceCommitOutcome::Accepted
        );
        let step = |now_millis| SourceMaintenance {
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = now_millis;
                move || decision_at_ms
            }),
            limit: std::num::NonZeroUsize::MIN,
        };
        for _ in 0..3 {
            let active = backend.maintain(step(1099)).await?;
            ensure!(active.examined == 1 && active.removed == 0);
        }
        ensure!(
            SourceEventCommit::commit(&backend, request(2, 1099, 2)).await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::RateLimited)
        );
        ensure!(backend.maintain(step(1100)).await?.removed == 0);
        let idle = backend.maintain(step(1100)).await?;
        ensure!(idle.examined == 1 && idle.removed == 1);
        let mut rate_key = scope_key(b'R', "test", "source")?;
        rate_key.extend_from_slice(&scope_epoch.to_be_bytes());
        let stream_key = {
            let mut key = scope_key(b'S', "test", "source")?;
            key.extend_from_slice(&scope_epoch.to_be_bytes());
            segment(&mut key, "ordered")?;
            key
        };
        let journal = backend.inner.read();
        ensure!(!journal.source.rates.contains_key(&rate_key));
        ensure!(
            journal
                .source
                .sequences
                .get(&stream_key)
                .map(|state| state.last_seq)
                == Some(1)
        );
        drop(journal);
        ensure!(
            SourceEventCommit::commit(&backend, request(3, 1101, 1)).await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::SequenceReplay {
                    last: 1,
                    seq: 1
                })
        );
        ensure!(
            SourceEventCommit::commit(&backend, request(4, 1101, 2)).await?
                == SourceCommitOutcome::Accepted
        );
        Ok(())
    }

    #[tokio::test]
    async fn installation_updates_and_retirement_fence_old_source_scope() -> anyhow::Result<()> {
        let backend = InMemoryBackend::new();
        let sink = Path::parse("state://events/external/test/source")?;
        let capacity = StreamCapacity {
            max_events: 4,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::integer(1);
        let taint = TaintSet::pristine();
        let first_epoch =
            install_source(&backend, "test", "source", &sink, &capacity, 1024, None).await?;
        let first = backend
            .load_installation("test")
            .await?
            .ok_or_else(|| anyhow::anyhow!("installation missing"))?;
        let request = |epoch, claim_id| SourceCommit {
            claim: SourceClaim {
                installation_id: "test",
                projection_id: "source",
                scope_epoch: epoch,
                stream_epoch: None,
                event_id: "same-event",
                claim_id: SourceClaimId::from_bytes([claim_id; 16]),
            },
            received_at_ms: 100,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = 100;
                move || decision_at_ms
            }),
            dedupe_window_ms: 1000,
            sink: &sink,
            capacity: &capacity,
            max_inline_payload_bytes: 1024,
            payload: &payload,
            taint: &taint,
            stream: None,
            rate_limit: None,
        };
        ensure!(
            SourceEventCommit::commit(&backend, request(first_epoch, 1)).await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(
            backend
                .compare_install(first.definition.clone(), None)
                .await?
                == ExternalInstallationMutation::Conflict {
                    current: Some(first.revision())
                }
        );
        ensure!(backend.load_installation("test").await? == Some(first.clone()));
        let ExternalInstallationMutation::Applied(Some(second)) = backend
            .compare_install(first.definition.clone(), Some(first.revision()))
            .await?
        else {
            anyhow::bail!("Source update was not applied")
        };
        let second_epoch = second
            .scope_epoch("source")
            .ok_or_else(|| anyhow::anyhow!("scope missing"))?;
        ensure!(
            second.installation_epoch == first.installation_epoch && second_epoch != first_epoch
        );
        ensure!(
            SourceEventCommit::commit(&backend, request(first_epoch, 2)).await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::ScopeInactive)
        );
        ensure!(
            SourceEventCommit::commit(&backend, request(second_epoch, 2)).await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(
            backend.compare_retire("test", second.revision()).await?
                == ExternalInstallationMutation::Applied(None)
        );
        ensure!(
            SourceEventCommit::commit(&backend, request(second_epoch, 3)).await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::ScopeInactive)
        );
        let reinstalled =
            install_source(&backend, "test", "source", &sink, &capacity, 1024, None).await?;
        let third = backend
            .load_installation("test")
            .await?
            .ok_or_else(|| anyhow::anyhow!("reinstalled record missing"))?;
        ensure!(
            reinstalled != second_epoch && third.installation_epoch != first.installation_epoch
        );
        ensure!(
            backend.compare_retire("test", first.revision()).await?
                == ExternalInstallationMutation::Conflict {
                    current: Some(third.revision())
                }
        );
        ensure!(
            backend
                .compare_install(first.definition.clone(), Some(first.revision()))
                .await?
                == ExternalInstallationMutation::Conflict {
                    current: Some(third.revision())
                }
        );
        ensure!(backend.load_installation("test").await? == Some(third));
        ensure!(
            SourceEventCommit::commit(&backend, request(reinstalled, 3)).await?
                == SourceCommitOutcome::Accepted
        );
        Ok(())
    }
}
