//! Bounded, execution-owned observations for volatile Stream submissions.

use super::{Completion, ConsoleError, ConsoleExecutionConfig, RetainedResult, map_value};
use prost::Message as _;
use std::sync::Arc;
use xolotl_types::{Failure, Value, ValueView};

// Charge per-row container and allocator overhead in addition to protobuf bytes.
const ROW_OVERHEAD: usize = 64;
const PAGE_ENVELOPE_RESERVE: usize = 256;
const PAGE_ENTRY_RESERVE: usize = 16;
const PAGE_NODE_RESERVE: usize = 16;
const MAX_PAGE_NODES: usize = 16_384;
// A retained event is nested below the page map and its entries list.
const EVENT_MAX_DEPTH: usize = xolotl_proto::MAX_VALUE_ENCODE_DEPTH - 4;
const PAGE_MAX_DEPTH: usize = xolotl_proto::MAX_VALUE_ENCODE_DEPTH - 2;

#[derive(Default)]
pub(super) struct OutputLog {
    events: Vec<StoredEvent>,
    charged_bytes: usize,
    terminal: Option<Terminal>,
}

struct StoredEvent {
    encoded: Arc<[u8]>,
    nodes: usize,
}

pub(super) struct EncodedEvent {
    bytes: Vec<u8>,
    nodes: usize,
}

#[derive(Clone)]
struct Terminal {
    outcome: String,
    stop_cause: Option<&'static str>,
    result_status: &'static str,
    unresolved_operation_count: usize,
    unresolved_identities_incomplete: bool,
}

pub(crate) struct OutputPage {
    entries: PageEntries,
    terminal: Option<Value>,
    next: u64,
    last: u64,
    complete: bool,
}

enum PageEntries {
    Encoded(Vec<Arc<[u8]>>),
}

#[derive(Clone, Copy)]
pub(crate) struct OutputPageRequest {
    pub after: u64,
    pub limit: usize,
    pub max_bytes: usize,
    pub event_limit: usize,
}

fn exhausted(dimension: &'static str) -> Failure {
    Failure::BudgetExhausted {
        dim: dimension.into(),
    }
}

fn bounded_protobuf(
    value: &Value,
    max_bytes: usize,
    max_nodes: usize,
    max_depth: usize,
) -> Result<xolotl_proto::xolotl::v1::Value, Failure> {
    let protobuf = xolotl_proto::value_to_pb_bounded(
        value,
        xolotl_proto::ValueEncodeLimits {
            max_nodes: max_nodes.min(max_bytes),
            max_depth,
            max_inline_bytes: max_bytes,
        },
    )
    .map_err(|_error| exhausted("console.output.event"))?;
    if protobuf.encoded_len() > max_bytes {
        return Err(exhausted("console.output.event"));
    }
    Ok(protobuf)
}

fn encode(
    value: &Value,
    max_bytes: usize,
    max_nodes: usize,
    max_depth: usize,
) -> Result<Vec<u8>, Failure> {
    Ok(bounded_protobuf(value, max_bytes, max_nodes, max_depth)?.encode_to_vec())
}

fn node_count(value: &Value) -> usize {
    match value.view() {
        ValueView::List(items) => 1 + items.iter().map(node_count).sum::<usize>(),
        ValueView::Map(entries) => 1 + entries.values().map(node_count).sum::<usize>(),
        _ => 1,
    }
}

fn decode(bytes: &[u8]) -> Result<Value, ConsoleError> {
    let protobuf = xolotl_proto::xolotl::v1::Value::decode(bytes)
        .map_err(|_error| ConsoleError::Operation("retained output is invalid".into()))?;
    xolotl_proto::value_from_pb(&protobuf)
        .map_err(|_error| ConsoleError::Operation("retained output is invalid".into()))
}

impl Terminal {
    fn from_completion(completion: &Completion) -> Self {
        Self {
            outcome: completion.outcome.clone(),
            stop_cause: completion.stop_cause,
            result_status: match completion.result {
                RetainedResult::Available(_) => "available",
                RetainedResult::Omitted(_) => "omitted",
            },
            unresolved_operation_count: completion.unresolved_operations.operation_ids.len(),
            unresolved_identities_incomplete: completion
                .unresolved_operations
                .identities_incomplete,
        }
    }

    fn event(&self, execution_id: &str, sequence: u64) -> Value {
        map_value([
            ("execution_id", Value::string(execution_id.into())),
            ("sequence", Value::integer(sequence as i64)),
            ("kind", Value::string("terminal".into())),
            ("outcome", Value::string(self.outcome.clone())),
            (
                "stop_cause",
                self.stop_cause
                    .map(|cause| Value::string(cause.into()))
                    .unwrap_or_else(Value::null),
            ),
            ("result_status", Value::string(self.result_status.into())),
            (
                "unresolved_operation_count",
                Value::integer(self.unresolved_operation_count as i64),
            ),
            (
                "unresolved_identities_incomplete",
                Value::boolean(self.unresolved_identities_incomplete),
            ),
            ("last_output_sequence", Value::integer(sequence as i64 - 1)),
        ])
    }
}

impl OutputLog {
    pub(super) fn next_sequence(&self, config: &ConsoleExecutionConfig) -> Result<u64, Failure> {
        if self.terminal.is_some() || self.events.len() + 1 >= config.max_output_events {
            return Err(exhausted("console.output.events"));
        }
        Ok(self.events.len() as u64 + 1)
    }

    pub(super) fn encode_event(
        execution_id: &str,
        sequence: u64,
        event: Value,
        event_limit: usize,
    ) -> Result<EncodedEvent, Failure> {
        let mut envelope = event
            .into_map()
            .ok_or_else(|| exhausted("console.output.event"))?;
        envelope
            .insert("execution_id".into(), Value::string(execution_id.into()))
            .map_err(|_error| exhausted("console.output.event"))?;
        envelope
            .insert("sequence".into(), Value::integer(sequence as i64))
            .map_err(|_error| exhausted("console.output.event"))?;
        let event = Value::from(envelope);
        let bytes = encode(
            &event,
            event_limit,
            MAX_PAGE_NODES - PAGE_NODE_RESERVE,
            EVENT_MAX_DEPTH,
        )?;
        Ok(EncodedEvent {
            bytes,
            nodes: node_count(&event),
        })
    }

    pub(super) fn append_encoded(
        &mut self,
        sequence: u64,
        event: EncodedEvent,
        config: &ConsoleExecutionConfig,
        event_limit: usize,
    ) -> Result<(), Failure> {
        if self.next_sequence(config)? != sequence {
            return Err(Failure::Custom {
                kind: "output_sequence".into(),
                message: "output append lost its sequence reservation".into(),
            });
        }
        let charge = event
            .bytes
            .len()
            .checked_add(ROW_OVERHEAD)
            .ok_or_else(|| exhausted("console.output.bytes"))?;
        let reserved_terminal = event_limit
            .checked_add(ROW_OVERHEAD)
            .ok_or_else(|| exhausted("console.output.bytes"))?;
        let next = self
            .charged_bytes
            .checked_add(charge)
            .and_then(|sum| sum.checked_add(reserved_terminal))
            .ok_or_else(|| exhausted("console.output.bytes"))?;
        if next > config.max_output_bytes_per_execution {
            return Err(exhausted("console.output.bytes"));
        }
        self.events.push(StoredEvent {
            encoded: Arc::from(event.bytes),
            nodes: event.nodes,
        });
        self.charged_bytes += charge;
        Ok(())
    }

    pub(super) fn seal(&mut self, completion: &Completion) {
        if self.terminal.is_none() {
            self.terminal = Some(Terminal::from_completion(completion));
        }
    }

    pub(super) fn update_terminal_outcome(&mut self, outcome: &str) {
        if let Some(terminal) = &mut self.terminal {
            terminal.outcome = outcome.into();
        }
    }

    pub(super) fn update_finalization(&mut self, completion: &Completion) {
        if self.terminal.is_some() {
            self.terminal = Some(Terminal::from_completion(completion));
        }
    }

    pub(super) fn last_sequence(&self) -> u64 {
        self.events.len() as u64 + u64::from(self.terminal.is_some())
    }

    pub(super) fn snapshot(
        &self,
        execution_id: &str,
        after: u64,
        limit: usize,
        max_bytes: usize,
        event_limit: usize,
    ) -> Result<OutputPage, ConsoleError> {
        let last = self.last_sequence();
        if after > last {
            return Err(ConsoleError::BadRequest("invalid output cursor".into()));
        }
        let start = usize::try_from(after)
            .map_err(|_error| ConsoleError::BadRequest("invalid output cursor".into()))?;
        let mut encoded = Vec::new();
        let mut bytes = PAGE_ENVELOPE_RESERVE;
        let node_limit = max_bytes.min(MAX_PAGE_NODES);
        let mut nodes = PAGE_NODE_RESERVE;
        let mut next = after;
        for event in self.events.iter().skip(start) {
            if encoded.len() >= limit {
                break;
            }
            let candidate = bytes
                .checked_add(event.encoded.len())
                .and_then(|total| total.checked_add(PAGE_ENTRY_RESERVE))
                .ok_or_else(|| {
                    ConsoleError::BadRequest("output page exceeds byte budget".into())
                })?;
            let candidate_nodes = nodes.checked_add(event.nodes).ok_or_else(|| {
                ConsoleError::BadRequest("output page exceeds node budget".into())
            })?;
            if candidate > max_bytes || candidate_nodes > node_limit {
                if encoded.is_empty() {
                    return Err(ConsoleError::BadRequest(
                        "output event exceeds page budget".into(),
                    ));
                }
                break;
            }
            encoded.push(event.encoded.clone());
            bytes = candidate;
            nodes = candidate_nodes;
            next += 1;
        }
        let terminal = if next == self.events.len() as u64
            && encoded.len() < limit
            && let Some(terminal) = &self.terminal
            && after < last
        {
            let event = terminal.event(execution_id, last);
            let size = bounded_protobuf(
                &event,
                event_limit,
                MAX_PAGE_NODES - PAGE_NODE_RESERVE,
                EVENT_MAX_DEPTH,
            )
            .map_err(|_error| ConsoleError::Operation("terminal output exceeds host limit".into()))?
            .encoded_len();
            if bytes
                .checked_add(size)
                .and_then(|total| total.checked_add(PAGE_ENTRY_RESERVE))
                .is_some_and(|total| total <= max_bytes)
                && nodes
                    .checked_add(node_count(&event))
                    .is_some_and(|total| total <= node_limit)
            {
                next = last;
                Some(event)
            } else if encoded.is_empty() {
                return Err(ConsoleError::BadRequest(
                    "output event exceeds page budget".into(),
                ));
            } else {
                None
            }
        } else {
            None
        };
        Ok(OutputPage {
            entries: PageEntries::Encoded(encoded),
            terminal,
            next,
            last,
            complete: self.terminal.is_some(),
        })
    }
}

impl OutputPage {
    pub(crate) fn has_entries(&self) -> bool {
        let count = match &self.entries {
            PageEntries::Encoded(entries) => entries.len(),
        };
        count != 0 || self.terminal.is_some()
    }

    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn into_value(self, max_bytes: usize) -> Result<Value, ConsoleError> {
        let mut entries = match self.entries {
            PageEntries::Encoded(encoded) => encoded
                .into_iter()
                .map(|entry| decode(&entry))
                .collect::<Result<Vec<_>, _>>()?,
        };
        if let Some(terminal) = self.terminal {
            entries.push(terminal);
        }
        let page = map_value([
            ("entries", Value::list(entries)),
            ("next_cursor", Value::integer(self.next as i64)),
            ("last_sequence", Value::integer(self.last as i64)),
            ("has_more", Value::boolean(self.next < self.last)),
            ("complete", Value::boolean(self.complete)),
        ]);
        encode(&page, max_bytes, MAX_PAGE_NODES, PAGE_MAX_DEPTH).map_err(|_error| {
            ConsoleError::Operation("output page exceeds host byte budget".into())
        })?;
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context as _, ensure};

    #[tokio::test]
    async fn delivery_token_rechecks_authority_and_record_identity() -> anyhow::Result<()> {
        let registry = super::super::ExecutionRegistry::new(ConsoleExecutionConfig {
            enabled: true,
            ..Default::default()
        })?;
        let owner: super::super::ExecutionOwner = serde_json::from_value(serde_json::json!({
            "username": "root", "account_id": "account", "authority_id": "local", "revocation_epoch": "1", "authority_ceiling": [],
            "credential_epoch": "credentials", "identity_path": "identity://console/accounts/account"
        }))?;
        let authority = (
            "perform".into(),
            xolotl_types::Path::parse("effect://jobs/stream")?,
        );
        let (registration, _stop, reference) =
            registry.register_authorized(super::super::Admission {
                owner: owner.clone(),
                authority: vec![authority],
                authority_candidates: vec![xolotl_types::Capability::parse(
                    "perform://effect/jobs/stream#stream",
                )?]
                .into(),
                reference: crate::protocol::ExecutionReference {
                    execution_id: None,
                    process_id: "7".into(),
                    program_id: "00".repeat(32),
                },
                budget: xolotl_types::BudgetSpec::default(),
                deadline: xolotl_kernel::host::system_now_millis() + 60_000,
                origin: None,
                stream_output: true,
            })?;
        let id = reference.execution_id.context("registered ID")?;
        ensure!(
            registry
                .result(&owner, &id, |candidates| {
                    candidates
                        .iter()
                        .all(|candidate| candidate.method.as_deref() == Some("stream"))
                })
                .is_ok()
        );
        ensure!(
            registry
                .result(&owner, &id, |candidates| {
                    candidates
                        .iter()
                        .all(|candidate| candidate.method.as_deref() == Some("other"))
                })
                .is_err()
        );
        let read = registry
            .output_page_for_delivery(
                &owner,
                &id,
                |candidates| {
                    candidates
                        .iter()
                        .all(|candidate| candidate.method.as_deref() == Some("stream"))
                },
                OutputPageRequest {
                    after: 0,
                    limit: 1,
                    max_bytes: 4096,
                    event_limit: 1024,
                },
            )
            .await?;
        let (_value, token) = read.into_value(4096)?;
        registry.validate_output_delivery(&owner, &token, |candidates| {
            candidates
                .iter()
                .all(|candidate| candidate.method.as_deref() == Some("stream"))
        })?;
        ensure!(
            registry
                .validate_output_delivery(&owner, &token, |candidates| {
                    candidates
                        .iter()
                        .all(|candidate| candidate.method.as_deref() == Some("other"))
                })
                .is_err()
        );
        registry.records().remove(token.sequence);
        ensure!(
            registry
                .validate_output_delivery(&owner, &token, |_| true)
                .is_err()
        );
        drop(registration);
        Ok(())
    }

    fn completion(outcome: &str) -> Completion {
        Completion {
            outcome: outcome.into(),
            stop_cause: None,
            result: RetainedResult::Omitted("test".into()),
            unresolved_operations: Default::default(),
            cleanup_complete: true,
            finalization: Default::default(),
        }
    }

    fn field<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a Value> {
        value
            .as_map()
            .and_then(|map| map.get(key))
            .with_context(|| format!("output test field {key}"))
    }

    fn append(
        log: &mut OutputLog,
        execution_id: &str,
        event: Value,
        config: &ConsoleExecutionConfig,
    ) -> Result<(), Failure> {
        let sequence = log.next_sequence(config)?;
        let encoded = OutputLog::encode_event(execution_id, sequence, event, 512)?;
        log.append_encoded(sequence, encoded, config, 512)
    }

    #[test]
    fn zero_output_seals_with_terminal_inside_minimum_page() -> anyhow::Result<()> {
        let mut log = OutputLog::default();
        log.seal(&completion("done"));
        let page = log.snapshot(&"x".repeat(32), 0, 1, 1024, 512)?;
        ensure!(page.complete());
        ensure!(page.has_entries());
        let value = page.into_value(1024)?;
        ensure!(field(&value, "next_cursor")?.as_int() == Some(1));
        ensure!(field(&value, "has_more")?.as_bool() == Some(false));
        let entries = field(&value, "entries")?.as_list().context("entries")?;
        ensure!(entries.len() == 1);
        ensure!(field(entries.get(0).context("terminal")?, "kind")?.as_str() == Some("terminal"));
        Ok(())
    }

    #[test]
    fn page_cursor_does_not_consume_other_observers_and_reserves_terminal() -> anyhow::Result<()> {
        let config = ConsoleExecutionConfig {
            max_output_events: 2,
            max_output_bytes_per_execution: 4096,
            ..Default::default()
        };
        let mut log = OutputLog::default();
        let event = map_value([("kind", Value::string("output".into()))]);
        append(&mut log, "execution", event, &config)?;
        ensure!(
            append(
                &mut log,
                "execution",
                map_value([("kind", Value::string("output".into()))]),
                &config,
            )
            .is_err()
        );
        log.seal(&completion("failed"));
        let first = log
            .snapshot("execution", 0, 1, 1024, 512)?
            .into_value(1024)?;
        let other = log
            .snapshot("execution", 0, 1, 1024, 512)?
            .into_value(1024)?;
        ensure!(first == other);
        ensure!(field(&first, "complete")?.as_bool() == Some(true));
        ensure!(field(&first, "has_more")?.as_bool() == Some(true));
        let terminal = log
            .snapshot("execution", 1, 1, 1024, 512)?
            .into_value(1024)?;
        let entries = field(&terminal, "entries")?.as_list().context("entries")?;
        ensure!(field(entries.get(0).context("terminal")?, "kind")?.as_str() == Some("terminal"));
        ensure!(field(&terminal, "next_cursor")?.as_int() == Some(2));
        ensure!(log.snapshot("execution", 3, 1, 1024, 512).is_err());
        Ok(())
    }

    #[test]
    fn many_compact_events_paginate_before_node_budget() -> anyhow::Result<()> {
        let config = ConsoleExecutionConfig::default();
        let mut log = OutputLog::default();
        let values = Value::list(vec![Value::null(); 100]);
        for _ in 0..200 {
            append(
                &mut log,
                "execution",
                map_value([
                    ("kind", Value::string("output".into())),
                    ("values", values.clone()),
                ]),
                &config,
            )?;
        }
        log.seal(&completion("done"));
        let mut cursor = 0;
        let mut total = 0;
        let mut pages = 0;
        loop {
            let page = log
                .snapshot("execution", cursor, 201, 256 * 1024, 512)?
                .into_value(256 * 1024)?;
            total += field(&page, "entries")?.as_list().context("entries")?.len();
            pages += 1;
            let next = u64::try_from(
                field(&page, "next_cursor")?
                    .as_int()
                    .context("next cursor")?,
            )?;
            ensure!(next > cursor);
            cursor = next;
            if field(&page, "has_more")?.as_bool() == Some(false) {
                break;
            }
        }
        ensure!(pages > 1);
        ensure!(total == 201);
        ensure!(cursor == 201);
        Ok(())
    }

    #[test]
    fn accepted_event_depth_can_be_replayed_inside_page() -> anyhow::Result<()> {
        let config = ConsoleExecutionConfig::default();
        let mut log = OutputLog::default();
        let mut nested = Value::null();
        for _ in 0..24 {
            nested = Value::list(vec![nested]);
        }
        append(
            &mut log,
            "execution",
            map_value([("nested", nested.clone())]),
            &config,
        )?;
        ensure!(
            append(
                &mut log,
                "execution",
                map_value([("nested", Value::list(vec![nested]))]),
                &config,
            )
            .is_err()
        );
        log.seal(&completion("done"));
        let page = log
            .snapshot("execution", 0, 2, 1024, 512)?
            .into_value(1024)?;
        ensure!(field(&page, "entries")?.as_list().context("entries")?.len() == 2);
        Ok(())
    }
}
