//! Shared admission, ownership and retention for independent executions.

use super::RuntimeConfigError;
use crate::auth::ExecutionOwner;
use crate::protocol::{ConsoleErrorCode, ConsoleFailure, ExecutionReference};
use crate::service::{ConsoleError, map_value, serde_value};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::sync::{Notify, watch};
use xolotl_kernel::{
    CleanupTicket,
    host::{HostDeadline, HostRuntime},
};
use xolotl_types::{Capability, OperationId, Path, Value};

mod cleanup;
mod config;
pub(crate) mod finalization;
pub use config::ConsoleExecutionConfig;
pub(crate) mod output;
mod root;

/// A reservation excludes concurrent attempts but does not authorize execution.
pub(crate) enum RootSubmissionProbe {
    Existing {
        /// Historical acceptance, including after result retirement.
        reference: ExecutionReference,
        /// Record visibility observed under the same lock as the receipt.
        retired: bool,
    },
    Preparing,
    Reserved(RootSubmissionReservation),
}

/// Missing volatile evidence never proves that a submission did not execute.
pub(crate) enum RootSubmissionEvidence {
    Unproven,
    Preparing,
    Accepted(ExecutionReference),
    Retired(ExecutionReference),
}

/// Owns exactly one preparing lease; dropping it cannot remove accepted evidence
/// or a replacement lease. No worker or kernel effects are owned at this stage.
pub(crate) struct RootSubmissionReservation {
    registry: Arc<ExecutionRegistry>,
    key: root::RootKey,
    lease: u64,
}

pub(crate) use output::OutputPageRequest;

/// One authorized directory observation paired with its bounded output page.
/// The service rechecks the observation after storage and account I/O.
pub(crate) struct OutputRead {
    page: output::OutputPage,
    sequence: u64,
    snapshot: ObservedRecord,
}

pub(crate) struct OutputReadToken {
    sequence: u64,
    snapshot: ObservedRecord,
}

impl OutputRead {
    pub(crate) fn has_entries(&self) -> bool {
        self.page.has_entries()
    }

    pub(crate) fn complete(&self) -> bool {
        self.page.complete()
    }

    pub(crate) fn into_value(
        self,
        max_bytes: usize,
    ) -> Result<(Value, OutputReadToken), ConsoleError> {
        let value = self.page.into_value(max_bytes)?;
        Ok((
            value,
            OutputReadToken {
                sequence: self.sequence,
                snapshot: self.snapshot,
            },
        ))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StopReason {
    Cancelled,
    Shutdown,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Completion {
    pub outcome: String,
    pub stop_cause: Option<&'static str>,
    pub result: RetainedResult,
    pub unresolved_operations: xolotl_types::UnresolvedOperations,
    pub cleanup_complete: bool,
    pub finalization: finalization::FinalizationProjection,
}

impl Completion {
    fn retain_finalization(&mut self, captured: &CapturedFinalization) {
        if matches!(
            self.finalization,
            finalization::FinalizationProjection::Pending
        ) {
            self.finalization = captured.projection.clone();
            self.unresolved_operations
                .merge(&captured.unresolved_operations);
        }
    }
}

struct CapturedFinalization {
    projection: finalization::FinalizationProjection,
    unresolved_operations: xolotl_types::UnresolvedOperations,
    complete: bool,
}

/// Own encoded bytes so driver-owned objects cannot silently escape the byte bound.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum RetainedResult {
    Available(Arc<Vec<u8>>),
    Omitted(String),
}

impl RetainedResult {
    pub fn encode(value: &Value, limit: usize) -> Self {
        let encoded = xolotl_proto::value_to_pb_bounded(
            value,
            xolotl_proto::ValueEncodeLimits {
                max_nodes: 16_384.min(limit),
                max_depth: xolotl_proto::MAX_VALUE_ENCODE_DEPTH - 2,
                max_inline_bytes: limit,
            },
        );
        match encoded {
            Ok(value) if value.encoded_len() <= limit => {
                Self::Available(Arc::new(value.encode_to_vec()))
            }
            _ => {
                Self::Omitted("result exceeds the host retention or Value conversion limit".into())
            }
        }
    }

    pub(crate) fn value(&self) -> Result<Value, ConsoleError> {
        match self {
            Self::Available(bytes) => {
                let value = xolotl_proto::xolotl::v1::Value::decode(bytes.as_slice())
                    .map_err(|error| ConsoleError::Operation(error.to_string()))?;
                xolotl_proto::value_from_pb(&value)
                    .map_err(|error| ConsoleError::Operation(error.to_string()))
            }
            Self::Omitted(message) => serde_value(ConsoleFailure::new(
                ConsoleErrorCode::Internal,
                message.clone(),
            )),
        }
    }
}

enum Phase {
    Running {
        stop: watch::Sender<Option<StopReason>>,
        completion: Option<Completion>,
    },
    Finished {
        completion: Completion,
        expires: HostDeadline,
        finished_at: i64,
        expires_at: i64,
    },
}

struct Record {
    id: String,
    owner: ExecutionOwner,
    authority: Arc<[(String, Path)]>,
    authority_candidates: Arc<[Capability]>,
    reference: ExecutionReference,
    budget: xolotl_types::BudgetSpec,
    origin: Option<ExecutionOrigin>,
    accepted: bool,
    cleanup_ticket: Option<CleanupTicket>,
    created_at: i64,
    deadline: i64,
    phase: Phase,
    output: Option<output::OutputLog>,
}

/// Causal identity of one child acceptance, independent of its newly allocated process.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionOrigin {
    pub execution_id: String,
    pub operation: OperationId,
}

impl ExecutionOrigin {
    fn value(&self) -> Value {
        map_value([
            ("execution_id", Value::string(self.execution_id.clone())),
            ("operation_id", Value::string(self.operation.to_string())),
        ])
    }
}

pub(crate) struct Admission {
    pub(crate) owner: ExecutionOwner,
    pub(crate) authority: Vec<(String, Path)>,
    pub(crate) authority_candidates: Arc<[Capability]>,
    pub(crate) reference: ExecutionReference,
    pub(crate) budget: xolotl_types::BudgetSpec,
    pub(crate) deadline: i64,
    pub(crate) origin: Option<ExecutionOrigin>,
    pub(crate) stream_output: bool,
}

/// Work independent of directory state is completed before taking Records.
/// A child obtains its candidates and budget from its source under that lock,
/// so their logical JSON bytes remain to be checked during atomic reservation.
struct PreparedReservation {
    id: String,
    authority_bytes_available: Option<usize>,
}

pub(crate) enum ChildRegistration {
    Existing(ExecutionReference),
    Reserved(
        Registration,
        watch::Receiver<Option<StopReason>>,
        ExecutionReference,
    ),
}

#[cfg(test)]
fn test_candidates(authority: &[(String, Path)]) -> Result<Vec<Capability>, ConsoleError> {
    authority
        .iter()
        .map(|(verb, path)| {
            xolotl_types::ResourceSelector::exact(verb, path)
                .map(|selector| selector.pattern)
                .map_err(|error| {
                    ConsoleError::Operation(format!("invalid test authority: {error}"))
                })
        })
        .collect()
}

/// Immutable fields needed by observers. The directory lock protects only
/// selection and this snapshot; authorization and value conversion use it
/// after the lock is released.
struct ObservedRecord {
    id: String,
    owner: ExecutionOwner,
    authority_candidates: Arc<[Capability]>,
    reference: ExecutionReference,
    budget: xolotl_types::BudgetSpec,
    origin: Option<ExecutionOrigin>,
    created_at: i64,
    deadline: i64,
    output_sequence: Option<u64>,
    phase: ObservedPhase,
}

enum ObservedPhase {
    Running {
        cancelling: bool,
        completion: Option<Completion>,
    },
    Finished {
        completion: Completion,
        finished_at: i64,
        expires_at: i64,
    },
}

impl Record {
    fn visible(&self, _now_millis: i64, now: HostDeadline) -> bool {
        !matches!(self.phase, Phase::Finished { expires, .. } if expires.elapsed_at(now).unwrap_or(true))
    }

    /// An active attempt may still execute or retain native captures.
    fn attempt_active(&self) -> bool {
        matches!(self.phase, Phase::Running { .. })
    }

    /// Admission capacity covers cleanup custody after an attempt exits too.
    fn custody_pending(&self) -> bool {
        match &self.phase {
            Phase::Running { .. } => true,
            Phase::Finished { completion, .. } => !completion.cleanup_complete,
        }
    }

    fn observe(&self) -> ObservedRecord {
        let phase = match &self.phase {
            Phase::Running { stop, completion } => ObservedPhase::Running {
                cancelling: stop.borrow().is_some(),
                completion: completion.clone(),
            },
            Phase::Finished {
                completion,
                finished_at,
                expires_at,
                ..
            } => ObservedPhase::Finished {
                completion: completion.clone(),
                finished_at: *finished_at,
                expires_at: *expires_at,
            },
        };
        ObservedRecord {
            id: self.id.clone(),
            owner: self.owner.clone(),
            authority_candidates: Arc::clone(&self.authority_candidates),
            reference: self.reference.clone(),
            budget: self.budget.clone(),
            origin: self.origin.clone(),
            created_at: self.created_at,
            deadline: self.deadline,
            output_sequence: self.output.as_ref().map(output::OutputLog::last_sequence),
            phase,
        }
    }
}

impl ObservedRecord {
    fn same_visible_identity(&self, record: &Record, now_millis: i64, now: HostDeadline) -> bool {
        record.visible(now_millis, now)
            && record.id == self.id
            && record.owner == self.owner
            && record.reference == self.reference
            && record.created_at == self.created_at
    }

    fn result(&self) -> Result<(Value, Value, Value), ConsoleError> {
        let completion = match &self.phase {
            ObservedPhase::Running { .. } => {
                return Ok((Value::null(), Value::null(), Value::null()));
            }
            ObservedPhase::Finished { completion, .. } => completion,
        };
        let unresolved = serde_value(&completion.unresolved_operations)?;
        match &completion.result {
            result @ RetainedResult::Available(_) => {
                Ok((result.value()?, Value::null(), unresolved))
            }
            result @ RetainedResult::Omitted(_) => Ok((Value::null(), result.value()?, unresolved)),
        }
    }

    fn metadata(&self) -> Result<Value, ConsoleError> {
        let (status, outcome, result, cleanup, finished_at, expires_at, unresolved) =
            match &self.phase {
                ObservedPhase::Running {
                    completion: Some(completion),
                    ..
                } => (
                    "finalizing",
                    Some(completion.outcome.as_str()),
                    "pending",
                    "pending",
                    None,
                    None,
                    Some(completion),
                ),
                ObservedPhase::Running { cancelling, .. } => (
                    if *cancelling { "cancelling" } else { "running" },
                    None,
                    "pending",
                    "pending",
                    None,
                    None,
                    None,
                ),
                ObservedPhase::Finished {
                    completion,
                    finished_at,
                    expires_at,
                } => (
                    "finished",
                    Some(completion.outcome.as_str()),
                    match completion.result {
                        RetainedResult::Available(_) => "available",
                        RetainedResult::Omitted(_) => "omitted",
                    },
                    if completion.cleanup_complete {
                        "complete"
                    } else {
                        "pending"
                    },
                    Some(*finished_at),
                    Some(*expires_at),
                    Some(completion),
                ),
            };
        Ok(map_value([
            ("execution_id", Value::string(self.id.clone())),
            ("execution", serde_value(&self.reference)?),
            ("budget", super::budget::value(&self.budget)?),
            (
                "source",
                self.origin
                    .as_ref()
                    .map(ExecutionOrigin::value)
                    .unwrap_or(Value::null()),
            ),
            ("lifetime", Value::string("host".into())),
            ("status", Value::string(status.into())),
            (
                "outcome",
                outcome
                    .map(|s| Value::string(s.into()))
                    .unwrap_or(Value::null()),
            ),
            (
                "stop_cause",
                unresolved
                    .and_then(|completion| completion.stop_cause)
                    .map(|cause| Value::string(cause.into()))
                    .unwrap_or_else(Value::null),
            ),
            ("result_status", Value::string(result.into())),
            (
                "unresolved_operation_count",
                unresolved
                    .map(|completion| {
                        Value::integer(completion.unresolved_operations.operation_ids.len() as i64)
                    })
                    .unwrap_or(Value::null()),
            ),
            (
                "unresolved_identities_incomplete",
                unresolved
                    .map(|completion| {
                        Value::boolean(completion.unresolved_operations.identities_incomplete)
                    })
                    .unwrap_or(Value::null()),
            ),
            ("cleanup_status", Value::string(cleanup.into())),
            ("created_at", Value::integer(self.created_at)),
            ("deadline", Value::integer(self.deadline)),
            (
                "output_observation",
                Value::boolean(self.output_sequence.is_some()),
            ),
            (
                "output_sequence",
                self.output_sequence
                    .map(|sequence| Value::integer(sequence as i64))
                    .unwrap_or(Value::null()),
            ),
            (
                "finished_at",
                finished_at.map(Value::integer).unwrap_or(Value::null()),
            ),
            (
                "expires_at",
                expires_at.map(Value::integer).unwrap_or(Value::null()),
            ),
        ]))
    }
}

#[derive(Default)]
struct Records {
    closed: bool,
    sequence: u64,
    retry_epoch: u64,
    root_lease: u64,
    root_aliases: HashMap<root::RootKey, root::RootAlias>,
    entries: BTreeMap<u64, Record>,
    /// Opaque execution IDs serve point reads; sequence remains the list order.
    id_to_sequence: HashMap<String, u64>,
}

impl Records {
    fn insert(&mut self, sequence: u64, record: Record) -> Result<(), ()> {
        if self.entries.contains_key(&sequence) || self.id_to_sequence.contains_key(&record.id) {
            return Err(());
        }
        let id = record.id.clone();
        self.entries.insert(sequence, record);
        self.id_to_sequence.insert(id, sequence);
        Ok(())
    }

    fn remove(&mut self, sequence: u64) -> Option<Record> {
        let record = self.entries.remove(&sequence)?;
        let indexed = self.id_to_sequence.remove(record.id.as_str());
        debug_assert_eq!(indexed, Some(sequence));
        Some(record)
    }

    fn sequence_for(&self, id: &str) -> Option<u64> {
        self.id_to_sequence.get(id).copied()
    }

    fn record_by_id(&self, id: &str) -> Option<(u64, &Record)> {
        let sequence = self.sequence_for(id)?;
        self.entries
            .get(&sequence)
            .filter(|record| record.id == id)
            .map(|record| (sequence, record))
    }

    #[cfg(test)]
    fn index_is_complete(&self) -> bool {
        self.entries.len() == self.id_to_sequence.len()
            && self
                .entries
                .iter()
                .all(|(sequence, record)| self.sequence_for(&record.id) == Some(*sequence))
    }
}

pub(crate) struct ExecutionRegistry {
    pub config: ConsoleExecutionConfig,
    pub(crate) cleanup: cleanup::Maintenance,
    host_runtime: HostRuntime,
    instance: String,
    records: Mutex<Records>,
    changed: Arc<Notify>,
}

struct ByteBudget(usize);

impl std::io::Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("authority byte limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ExecutionRegistry {
    fn authority_limit_error() -> ConsoleError {
        ConsoleError::BadRequest("execution authority exceeds the host retention limit".into())
    }

    fn new_execution_id() -> Result<String, ConsoleError> {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).map_err(|_error| {
            ConsoleError::Operation("execution identity entropy is unavailable".into())
        })?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn prepare_reservation(
        &self,
        owner: &ExecutionOwner,
        authority: &[(String, Path)],
        authority_candidates: &[Capability],
        origin: Option<&ExecutionOrigin>,
        budget: &xolotl_types::BudgetSpec,
    ) -> Result<PreparedReservation, ConsoleError> {
        let available = self.prepare_authority_bytes(owner, authority, origin)?;
        Self::check_retained_authority_bytes(available, authority_candidates, budget)?;
        Ok(PreparedReservation {
            id: Self::new_execution_id()?,
            authority_bytes_available: None,
        })
    }

    fn prepare_child_reservation(
        &self,
        owner: &ExecutionOwner,
        authority: &[(String, Path)],
        origin: &ExecutionOrigin,
    ) -> Result<PreparedReservation, ConsoleError> {
        let available = self.prepare_authority_bytes(owner, authority, Some(origin))?;
        Ok(PreparedReservation {
            id: Self::new_execution_id()?,
            authority_bytes_available: Some(available),
        })
    }

    fn prepare_authority_bytes(
        &self,
        owner: &ExecutionOwner,
        authority: &[(String, Path)],
        origin: Option<&ExecutionOrigin>,
    ) -> Result<usize, ConsoleError> {
        let mut bytes = ByteBudget(self.config.max_authority_bytes);
        serde_json::to_writer(&mut bytes, &(owner, authority, origin))
            .map_err(|_error| Self::authority_limit_error())?;
        bytes
            .0
            .checked_sub(2)
            .ok_or_else(Self::authority_limit_error)
    }

    fn check_retained_authority_bytes(
        available: usize,
        authority_candidates: &[Capability],
        budget: &xolotl_types::BudgetSpec,
    ) -> Result<(), ConsoleError> {
        let mut bytes = ByteBudget(available);
        serde_json::to_writer(&mut bytes, authority_candidates)
            .map_err(|_error| Self::authority_limit_error())?;
        serde_json::to_writer(&mut bytes, budget).map_err(|_error| Self::authority_limit_error())
    }

    #[cfg(test)]
    pub fn new(config: ConsoleExecutionConfig) -> Result<Arc<Self>, crate::ConsoleConfigError> {
        Self::new_with_host_runtime(config, HostRuntime::default())
    }

    pub fn new_with_host_runtime(
        config: ConsoleExecutionConfig,
        host_runtime: HostRuntime,
    ) -> Result<Arc<Self>, crate::ConsoleConfigError> {
        let records = Records::default();
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).map_err(|_error| RuntimeConfigError::Entropy)?;
        Ok(Arc::new(Self {
            config,
            cleanup: cleanup::Maintenance::default(),
            host_runtime,
            instance: URL_SAFE_NO_PAD.encode(bytes),
            records: Mutex::new(records),
            changed: Arc::new(Notify::new()),
        }))
    }

    fn records(&self) -> MutexGuard<'_, Records> {
        self.records.lock().unwrap_or_else(|error| {
            let mut records = error.into_inner();
            records.closed = true;
            records
        })
    }

    /// Expiry eviction is separate from targeted cleanup evidence reconciliation.
    fn maintain_volatile_in(&self, records: &mut Records) {
        let now = self.host_runtime.now();
        // Most accesses have nothing to retire. Avoid allocating a copy of
        // every active execution ID (and mutating the directory) on that path.
        let mut expiring = false;
        let mut needs_source_check = false;
        for record in records.entries.values() {
            if matches!(record.phase, Phase::Finished { expires, .. } if expires.elapsed_at(now).unwrap_or(true))
                && !record.custody_pending()
            {
                expiring = true;
                if record.origin.is_some() {
                    needs_source_check = true;
                    break;
                }
            }
        }
        let mut removed = false;
        if expiring {
            let before = records.entries.len();
            // An expired child's acceptance receipt remains available while
            // its source can execute, although its result is no longer visible.
            // Only those children require a source lookup during this pass.
            let active: std::collections::BTreeSet<_> = if needs_source_check {
                records
                    .entries
                    .values()
                    .filter(|record| record.attempt_active())
                    .map(|record| record.id.clone())
                    .collect()
            } else {
                std::collections::BTreeSet::new()
            };
            let Records {
                entries,
                id_to_sequence,
                ..
            } = records;
            entries.retain(|sequence, record| {
                let keep = !matches!(record.phase, Phase::Finished { expires, .. } if expires.elapsed_at(now).unwrap_or(true))
                    || record.custody_pending()
                    || record
                        .origin
                        .as_ref()
                        .is_some_and(|origin| active.contains(&origin.execution_id));
                if !keep {
                    let indexed = id_to_sequence.remove(record.id.as_str());
                    debug_assert_eq!(indexed, Some(*sequence));
                }
                keep
            });
            removed = records.entries.len() != before;
        }
        if removed {
            self.changed.notify_waiters();
        }
        records.reclaim_closed_root_aliases();
    }

    pub(crate) fn maintain_volatile(&self) {
        for candidate in self.pending_cleanup() {
            self.acknowledge_cleanup(&candidate);
        }
        let mut records = self.records();
        self.maintain_volatile_in(&mut records);
    }

    fn capture_finalization(&self, sequence: u64) -> Option<CapturedFinalization> {
        let (ticket, saved) = {
            let records = self.records();
            let record = records.entries.get(&sequence)?;
            let saved = match &record.phase {
                Phase::Running { completion, .. } => completion
                    .as_ref()
                    .map(|completion| completion.finalization.clone()),
                Phase::Finished { completion, .. } => Some(completion.finalization.clone()),
            };
            (record.cleanup_ticket.clone()?, saved)
        };
        let report = ticket.finalization_report();
        let projection = match saved {
            Some(
                saved @ (finalization::FinalizationProjection::Committed(_)
                | finalization::FinalizationProjection::Omitted),
            ) => saved,
            _ => report
                .as_ref()
                .map_or(finalization::FinalizationProjection::Pending, |report| {
                    finalization::FinalizationProjection::encode(
                        report,
                        self.config.max_finalization_bytes,
                    )
                }),
        };
        Some(CapturedFinalization {
            projection,
            unresolved_operations: ticket.unresolved_operations().unwrap_or_default(),
            complete: report.is_some() && ticket.is_complete(),
        })
    }

    fn reconcile_cleanup(&self, sequence: u64) {
        let candidate = {
            let records = self.records();
            records.entries.get(&sequence).and_then(|record| {
                if !matches!(&record.phase, Phase::Finished { completion, .. } if !completion.cleanup_complete) {
                    return None;
                }
                record.cleanup_ticket.as_ref().map(|ticket| cleanup::PendingCleanup {
                    sequence,
                    process: ticket.process(),
                    ticket: ticket.clone(),
                })
            })
        };
        if let Some(candidate) = candidate {
            self.acknowledge_cleanup(&candidate);
        }
    }

    fn observe_record(
        &self,
        owner: &ExecutionOwner,
        id: &str,
    ) -> Result<(u64, ObservedRecord), ConsoleError> {
        let sequence = {
            let records = self.records();
            self.find(&records, owner, id)?.0
        };
        self.reconcile_cleanup(sequence);
        let records = self.records();
        let (current, record) = self.find(&records, owner, id)?;
        if current != sequence {
            return Err(ConsoleError::BadRequest("execution is unavailable".into()));
        }
        Ok((sequence, record.observe()))
    }

    pub fn accepting(&self) -> bool {
        // Discovery observes admission without scanning results or doing storage
        // cleanup. Registration performs volatile maintenance before quota checks.
        self.config.enabled && self.records.lock().is_ok_and(|records| !records.closed)
    }

    pub fn closed(&self) -> bool {
        self.records().closed
    }

    pub fn close(&self) {
        self.records().closed = true;
        self.changed.notify_waiters();
    }

    #[cfg(test)]
    pub fn register(
        self: &Arc<Self>,
        owner: ExecutionOwner,
        authority: Vec<(String, Path)>,
        reference: ExecutionReference,
        deadline: i64,
        budget: xolotl_types::BudgetSpec,
    ) -> Result<
        (
            Registration,
            watch::Receiver<Option<StopReason>>,
            ExecutionReference,
        ),
        ConsoleError,
    > {
        let candidates = test_candidates(&authority)?;
        self.register_authorized(Admission {
            owner,
            authority,
            authority_candidates: Arc::from(candidates),
            reference,
            budget,
            deadline,
            origin: None,
            stream_output: false,
        })
    }

    pub(crate) fn register_authorized(
        self: &Arc<Self>,
        admission: Admission,
    ) -> Result<
        (
            Registration,
            watch::Receiver<Option<StopReason>>,
            ExecutionReference,
        ),
        ConsoleError,
    > {
        let (stop, receive) = watch::channel(None);
        let (sequence, reference) = self.reserve(admission, |_, _| {
            Ok(Phase::Running {
                stop,
                completion: None,
            })
        })?;
        Ok((
            Registration {
                registry: self.clone(),
                sequence,
                finished: false,
            },
            receive,
            reference,
        ))
    }

    fn reserve(
        &self,
        admission: Admission,
        phase: impl FnOnce(&ExecutionReference, i64) -> Result<Phase, ConsoleError>,
    ) -> Result<(u64, ExecutionReference), ConsoleError> {
        let prepared = self.prepare_reservation(
            &admission.owner,
            &admission.authority,
            &admission.authority_candidates,
            admission.origin.as_ref(),
            &admission.budget,
        )?;
        self.maintain_volatile();
        let mut records = self.records();
        self.reserve_in(&mut records, admission, prepared, phase)
    }

    /// Reserve and reconcile under one registry lock. A merely reserved child
    /// is not an accepted receipt: its kernel admission may still be rejected.
    pub fn register_child(
        self: &Arc<Self>,
        owner: ExecutionOwner,
        authority: Vec<(String, Path)>,
        reference: ExecutionReference,
        deadline: i64,
        origin: ExecutionOrigin,
    ) -> Result<ChildRegistration, ConsoleError> {
        let prepared = self.prepare_child_reservation(&owner, &authority, &origin)?;
        self.maintain_volatile();
        let mut records = self.records();
        self.maintain_volatile_in(&mut records);
        if !self.config.enabled || records.closed {
            return Err(ConsoleError::BadRequest(
                "independent execution admission is closed".into(),
            ));
        }
        let source = records
            .record_by_id(&origin.execution_id)
            .map(|(_, record)| record)
            .ok_or_else(|| {
                ConsoleError::BadRequest("child source execution is unavailable".into())
            })?;
        if !source.attempt_active()
            || source.owner != owner
            || source.reference.process_id != origin.operation.process.get().to_string()
            || source.reference.program_id != reference.program_id
            || source.authority.as_ref() != authority.as_slice()
        {
            return Err(ConsoleError::BadRequest(
                "child source authority does not match".into(),
            ));
        }
        let deadline = deadline.min(source.deadline);
        if let Some(existing) = records
            .entries
            .values()
            .find(|record| record.origin.as_ref() == Some(&origin))
        {
            return if existing.accepted {
                Ok(ChildRegistration::Existing(existing.reference.clone()))
            } else {
                Err(ConsoleError::RateLimited)
            };
        }
        let budget = source.budget.clone();
        let authority_candidates = Arc::clone(&source.authority_candidates);
        let (stop, receive) = watch::channel(None);
        let (sequence, reference) = self.reserve_in(
            &mut records,
            Admission {
                owner,
                authority,
                authority_candidates,
                reference,
                deadline,
                origin: Some(origin),
                budget,
                stream_output: false,
            },
            prepared,
            |_, _| {
                Ok(Phase::Running {
                    stop,
                    completion: None,
                })
            },
        )?;
        Ok(ChildRegistration::Reserved(
            Registration {
                registry: self.clone(),
                sequence,
                finished: false,
            },
            receive,
            reference,
        ))
    }

    fn reserve_in(
        &self,
        records: &mut Records,
        admission: Admission,
        prepared: PreparedReservation,
        phase: impl FnOnce(&ExecutionReference, i64) -> Result<Phase, ConsoleError>,
    ) -> Result<(u64, ExecutionReference), ConsoleError> {
        self.maintain_volatile_in(records);
        let Admission {
            owner,
            authority,
            authority_candidates,
            mut reference,
            budget,
            deadline,
            origin,
            stream_output,
        } = admission;
        if !self.config.enabled || records.closed {
            return Err(ConsoleError::BadRequest(
                "independent execution admission is closed".into(),
            ));
        }
        if authority.iter().any(|(verb, path)| {
            !authority_candidates
                .iter()
                .any(|candidate| candidate.matches_path_structure(verb, path))
        }) || authority_candidates.iter().any(|candidate| {
            !authority
                .iter()
                .any(|(verb, path)| candidate.matches_path_structure(verb, path))
        }) {
            return Err(ConsoleError::BadRequest(
                "independent execution authority candidates do not match its operations".into(),
            ));
        }
        let (alias_records, alias_account_records) = records.root_alias_charges(&owner);
        if records.entries.len() + alias_records >= self.config.max_records {
            return Err(ConsoleError::RateLimited);
        }
        // All four quotas refer to the same admitted rows. Count them in one
        // pass under the directory lock, including rows held for cleanup.
        let mut account_records = alias_account_records;
        if account_records >= self.config.max_records_per_account {
            return Err(ConsoleError::RateLimited);
        }
        let mut concurrent = 0;
        let mut account_concurrent = 0;
        let mut output_records = 0;
        for record in records.entries.values() {
            let same_account = record.owner.same_account(&owner);
            account_records += usize::from(same_account);
            let pending = record.custody_pending();
            concurrent += usize::from(pending);
            account_concurrent += usize::from(same_account && pending);
            if stream_output {
                let reserved = record.output.is_some();
                output_records += usize::from(reserved);
            }
            if account_records >= self.config.max_records_per_account
                || concurrent >= self.config.max_concurrent
                || account_concurrent >= self.config.max_concurrent_per_account
            {
                return Err(ConsoleError::RateLimited);
            }
        }
        if stream_output {
            let reserved = output_records
                .checked_add(1)
                .and_then(|count| count.checked_mul(self.config.max_output_bytes_per_execution))
                .ok_or(ConsoleError::RateLimited)?;
            if reserved > self.config.max_output_bytes_total {
                return Err(ConsoleError::RateLimited);
            }
        }
        if let Some(available) = prepared.authority_bytes_available {
            Self::check_retained_authority_bytes(available, &authority_candidates, &budget)?;
        }
        if records.sequence_for(&prepared.id).is_some() {
            return Err(ConsoleError::Operation(
                "execution identity collision".into(),
            ));
        }
        let sequence = records
            .sequence
            .checked_add(1)
            .ok_or(ConsoleError::RateLimited)?;
        records.sequence = sequence;
        let id = prepared.id;
        reference.execution_id = Some(id.clone());
        let created_at = self.host_runtime.now_millis();
        let phase = phase(&reference, created_at)?;
        records
            .insert(
                sequence,
                Record {
                    id,
                    owner,
                    authority: Arc::from(authority),
                    authority_candidates,
                    reference: reference.clone(),
                    budget,
                    accepted: origin.is_none(),
                    cleanup_ticket: None,
                    origin,
                    created_at,
                    deadline,
                    phase,
                    output: stream_output.then(output::OutputLog::default),
                },
            )
            .map_err(|()| ConsoleError::Operation("execution identity collision".into()))?;
        Ok((sequence, reference))
    }

    fn find<'a>(
        &self,
        records: &'a Records,
        owner: &ExecutionOwner,
        id: &str,
    ) -> Result<(u64, &'a Record), ConsoleError> {
        records
            .record_by_id(id)
            .filter(|(_, record)| {
                record.owner.same_account(owner)
                    && record.visible(self.host_runtime.now_millis(), self.host_runtime.now())
            })
            .ok_or_else(|| ConsoleError::BadRequest("execution is unavailable".into()))
    }

    fn ensure_visible_snapshot(
        &self,
        owner: &ExecutionOwner,
        sequence: u64,
        snapshot: &ObservedRecord,
    ) -> Result<(), ConsoleError> {
        let records = self.records();
        if records.entries.get(&sequence).is_some_and(|record| {
            record.owner.same_account(owner)
                && snapshot.same_visible_identity(
                    record,
                    self.host_runtime.now_millis(),
                    self.host_runtime.now(),
                )
        }) {
            Ok(())
        } else {
            Err(ConsoleError::BadRequest("execution is unavailable".into()))
        }
    }

    pub fn get(&self, owner: &ExecutionOwner, id: &str) -> Result<Value, ConsoleError> {
        let (sequence, snapshot) = self.observe_record(owner, id)?;
        let value = snapshot.metadata()?;
        self.ensure_visible_snapshot(owner, sequence, &snapshot)?;
        Ok(value)
    }

    pub fn result(
        &self,
        owner: &ExecutionOwner,
        id: &str,
        allowed: impl Fn(&[Capability]) -> bool,
    ) -> Result<Value, ConsoleError> {
        let (sequence, snapshot) = self.observe_record(owner, id)?;
        if !allowed(&snapshot.authority_candidates) {
            return Err(crate::auth::AuthError::PermissionDenied.into());
        }
        let (output, failure, unresolved) = snapshot.result()?;
        let metadata = snapshot.metadata()?;
        let finalization = match &snapshot.phase {
            ObservedPhase::Finished { completion, .. } => completion.finalization.value()?,
            _ => Value::null(),
        };
        self.ensure_visible_snapshot(owner, sequence, &snapshot)?;
        Ok(map_value([
            ("record", metadata),
            ("output", output),
            ("retention_failure", failure),
            ("unresolved_operations", unresolved),
            ("finalization", finalization),
        ]))
    }

    /// Register interest before checking the log, so an append between check
    /// and wait cannot be missed. Wakes may concern another execution.
    pub fn output_notified(&self) -> tokio::sync::futures::OwnedNotified {
        self.changed.clone().notified_owned()
    }

    fn snapshot_volatile_output(
        &self,
        sequence: u64,
        snapshot: &ObservedRecord,
        request: OutputPageRequest,
    ) -> Result<output::OutputPage, ConsoleError> {
        let records = self.records();
        let record = records
            .entries
            .get(&sequence)
            .filter(|record| {
                snapshot.same_visible_identity(
                    record,
                    self.host_runtime.now_millis(),
                    self.host_runtime.now(),
                )
            })
            .ok_or_else(|| {
                ConsoleError::BadRequest("execution output unavailable or expired".into())
            })?;
        let log = record
            .output
            .as_ref()
            .ok_or_else(|| ConsoleError::BadRequest("execution has no Stream output log".into()))?;
        log.snapshot(
            &snapshot.id,
            request.after,
            request.limit,
            request.max_bytes,
            request.event_limit,
        )
    }

    /// Snapshot bounded output without retaining the directory lock for delivery.
    /// The returned observation remains opaque until the service has repeated
    /// session, MFA and grant checks immediately before delivery.
    pub async fn output_page_for_delivery(
        self: &Arc<Self>,
        owner: &ExecutionOwner,
        id: &str,
        allowed: impl Fn(&[Capability]) -> bool,
        request: OutputPageRequest,
    ) -> Result<OutputRead, ConsoleError> {
        let (sequence, snapshot) = self.observe_record(owner, id).map_err(|_error| {
            ConsoleError::BadRequest("execution output unavailable or expired".into())
        })?;
        if !allowed(&snapshot.authority_candidates) {
            return Err(crate::auth::AuthError::PermissionDenied.into());
        }

        let page = self.snapshot_volatile_output(sequence, &snapshot, request)?;
        self.ensure_visible_snapshot(owner, sequence, &snapshot)?;
        Ok(OutputRead {
            page,
            sequence,
            snapshot,
        })
    }

    /// Repeat this after all blocking reads and before response delivery.
    pub fn validate_output_delivery(
        &self,
        owner: &ExecutionOwner,
        read: &OutputReadToken,
        allowed: impl Fn(&[Capability]) -> bool,
    ) -> Result<(), ConsoleError> {
        if !allowed(&read.snapshot.authority_candidates) {
            return Err(crate::auth::AuthError::PermissionDenied.into());
        }
        self.ensure_visible_snapshot(owner, read.sequence, &read.snapshot)
    }

    pub async fn cancel(
        self: &Arc<Self>,
        owner: &ExecutionOwner,
        id: &str,
    ) -> Result<Value, ConsoleError> {
        self.observe_record(owner, id)?;
        let (sequence, snapshot) = {
            let mut records = self.records();
            let sequence = self.find(&records, owner, id)?.0;
            let record = records
                .entries
                .get_mut(&sequence)
                .ok_or_else(|| ConsoleError::Operation("execution record disappeared".into()))?;
            if let Phase::Running { stop, .. } = &record.phase {
                stop.send_replace(Some(StopReason::Cancelled));
            }
            (sequence, record.observe())
        };
        let value = snapshot.metadata()?;
        self.ensure_visible_snapshot(owner, sequence, &snapshot)?;
        Ok(value)
    }

    fn forget_key(
        records: &Records,
        owner: &ExecutionOwner,
        id: &str,
    ) -> Result<u64, ConsoleError> {
        // Expiry hides the result, but the owning account may still delete
        // retained evidence by its known ID after an automatic retry fails.
        let (key, record) = records
            .record_by_id(id)
            .filter(|(_, record)| record.owner.same_account(owner))
            .ok_or_else(|| ConsoleError::BadRequest("execution is unavailable".into()))?;
        if record.custody_pending() {
            return Err(ConsoleError::BadRequest(
                "executions with active attempts or pending cleanup cannot be forgotten".into(),
            ));
        }
        if record.origin.as_ref().is_some_and(|origin| {
            records
                .record_by_id(&origin.execution_id)
                .is_some_and(|(_, source)| source.attempt_active())
        }) {
            return Err(ConsoleError::BadRequest(
                "child acceptance is retained while its source execution is active".into(),
            ));
        }
        Ok(key)
    }

    pub async fn forget(
        self: &Arc<Self>,
        owner: &ExecutionOwner,
        id: &str,
    ) -> Result<Value, ConsoleError> {
        let sequence = {
            let records = self.records();
            records
                .record_by_id(id)
                .filter(|(_, record)| record.owner.same_account(owner))
                .map(|(sequence, _)| sequence)
                .ok_or_else(|| ConsoleError::BadRequest("execution is unavailable".into()))?
        };
        self.reconcile_cleanup(sequence);
        {
            let mut records = self.records();
            let key = Self::forget_key(&records, owner, id)?;
            records.remove(key);
            records.reclaim_closed_root_aliases();
            self.changed.notify_waiters();
        }
        Ok(map_value([("forgotten", Value::boolean(true))]))
    }

    pub fn list(
        &self,
        owner: &ExecutionOwner,
        cursor: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Value, ConsoleError> {
        let invalid = || ConsoleError::BadRequest("invalid execution cursor".into());
        let after = if let Some(cursor) = cursor {
            if cursor.len() > 1024 {
                return Err(invalid());
            }
            let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_error| invalid())?;
            let (instance, account, after): (String, String, u64) =
                serde_json::from_slice(&bytes).map_err(|_error| invalid())?;
            if instance != self.instance || account != owner.account_id {
                return Err(invalid());
            }
            after
        } else {
            0
        };
        let mut snapshots: Vec<_> = {
            let records = self.records();
            let now_millis = self.host_runtime.now_millis();
            let now = self.host_runtime.now();
            records
                .entries
                .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                .filter(|(_, record)| {
                    record.owner.same_account(owner) && record.visible(now_millis, now)
                })
                .take(limit.saturating_add(1))
                .map(|(sequence, record)| (*sequence, record.observe()))
                .collect()
        };
        for (sequence, snapshot) in &mut snapshots {
            self.reconcile_cleanup(*sequence);
            let records = self.records();
            let record = records
                .entries
                .get(sequence)
                .filter(|record| {
                    snapshot.same_visible_identity(
                        record,
                        self.host_runtime.now_millis(),
                        self.host_runtime.now(),
                    )
                })
                .ok_or_else(|| ConsoleError::BadRequest("execution is unavailable".into()))?;
            *snapshot = record.observe();
        }
        let mut entries = Vec::new();
        let mut last = after;
        let mut bytes = 0;
        let mut next = None;
        for (sequence, snapshot) in &snapshots {
            let row = snapshot.metadata()?;
            let size = serde_json::to_vec(&row)
                .map_err(|error| ConsoleError::Operation(error.to_string()))?
                .len();
            if entries.len() >= limit || bytes + size > max_bytes {
                if entries.is_empty() {
                    return Err(ConsoleError::BadRequest(
                        "execution record exceeds page budget".into(),
                    ));
                }
                let bytes = serde_json::to_vec(&(&self.instance, &owner.account_id, last))
                    .map_err(|error| ConsoleError::Operation(error.to_string()))?;
                next = Some(URL_SAFE_NO_PAD.encode(bytes));
                break;
            }
            entries.push(row);
            last = *sequence;
            bytes += size;
        }
        {
            let records = self.records();
            let now_millis = self.host_runtime.now_millis();
            let now = self.host_runtime.now();
            for (sequence, snapshot) in snapshots.iter().take(entries.len()) {
                if !records.entries.get(sequence).is_some_and(|record| {
                    record.owner.same_account(owner)
                        && snapshot.same_visible_identity(record, now_millis, now)
                }) {
                    return Err(ConsoleError::BadRequest("execution is unavailable".into()));
                }
            }
        }
        Ok(map_value([
            ("entries", Value::list(entries)),
            (
                "next_cursor",
                next.map(Value::string).unwrap_or(Value::null()),
            ),
        ]))
    }

    /// Close admission and wait for volatile attempts to exit. Failed cleanup
    /// remains reserved for reconciliation; it cannot make shutdown wait forever.
    /// Concurrent shutdown callers are supported.
    pub async fn shutdown(&self) {
        self.close();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let active = {
                let records = self.records();
                let mut active = false;
                for record in records.entries.values() {
                    if let Phase::Running { stop, .. } = &record.phase {
                        stop.send_replace(Some(StopReason::Shutdown));
                        active = true;
                    }
                }
                active
            };
            if !active {
                return;
            }
            changed.await;
        }
    }
}

/// A worker must publish a terminal record even if it panics or is dropped.
pub(crate) struct Registration {
    registry: Arc<ExecutionRegistry>,
    sequence: u64,
    finished: bool,
}

impl Registration {
    pub fn append_output(
        &self,
        event: Value,
        event_limit: usize,
    ) -> Result<(), xolotl_types::Failure> {
        let (id, sequence) = {
            let records = self.registry.records();
            let record = records
                .entries
                .get(&self.sequence)
                .ok_or(xolotl_types::Failure::Cancelled)?;
            let output = record
                .output
                .as_ref()
                .ok_or(xolotl_types::Failure::InvalidInput {
                    reason: "execution has no Stream output log".into(),
                })?;
            (
                record.id.clone(),
                output.next_sequence(&self.registry.config)?,
            )
        };
        // Protobuf conversion can traverse a large Value; do it without holding
        // the global execution-directory lock. The second lock checks sequence.
        let encoded = output::OutputLog::encode_event(&id, sequence, event, event_limit)?;
        let mut records = self.registry.records();
        let record = records
            .entries
            .get_mut(&self.sequence)
            .ok_or(xolotl_types::Failure::Cancelled)?;
        let output = record
            .output
            .as_mut()
            .ok_or(xolotl_types::Failure::InvalidInput {
                reason: "execution has no Stream output log".into(),
            })?;
        output.append_encoded(sequence, encoded, &self.registry.config, event_limit)?;
        self.registry.changed.notify_waiters();
        Ok(())
    }

    /// Called only once the kernel owns the child process, before Driver dispatch.
    pub fn accepted(&self) {
        if let Some(record) = self.registry.records().entries.get_mut(&self.sequence) {
            record.accepted = true;
        }
    }
    /// Reject a reserved child before kernel process admission. No execution ran.
    /// Already accepted roots retain cleanup custody and publish interruption.
    pub fn reject(&mut self) {
        if !self.finished {
            let mut records = self.registry.records();
            if records.root_accepted(self.sequence) {
                drop(records);
                self.publish(None);
                return;
            }
            records.remove(self.sequence);
            records.reclaim_closed_root_aliases();
            self.finished = true;
            self.registry.changed.notify_waiters();
        }
    }

    pub fn record_body(&self, completion: Completion) {
        // A terminal callback also proves kernel admission, including a child
        // forcibly abandoned before its preparation future was first polled.
        self.accepted();
        if let Some(record) = self.registry.records().entries.get_mut(&self.sequence)
            && let Phase::Running {
                completion: retained,
                ..
            } = &mut record.phase
        {
            match retained {
                Some(retained) => {
                    retained.stop_cause = retained.stop_cause.or(completion.stop_cause);
                }
                None => *retained = Some(completion),
            }
        }
    }

    pub(crate) fn record_stop_cause(&self, stop_cause: &'static str) {
        if let Some(record) = self.registry.records().entries.get_mut(&self.sequence)
            && let Phase::Running {
                completion: Some(completion),
                ..
            } = &mut record.phase
        {
            completion.stop_cause.get_or_insert(stop_cause);
        }
    }

    pub(crate) fn body_recorded(&self) -> bool {
        matches!(
            self.registry
                .records()
                .entries
                .get(&self.sequence)
                .map(|record| &record.phase),
            Some(
                Phase::Running {
                    completion: Some(_),
                    ..
                } | Phase::Finished { .. }
            )
        )
    }

    /// Bind cleanup custody before the native attempt can disappear. Keep the
    /// first ticket so later callbacks cannot replace the admitted process.
    pub(crate) fn bind_cleanup(&self, ticket: CleanupTicket) -> Result<(), ConsoleError> {
        let mut records = self.registry.records();
        let record = records.entries.get_mut(&self.sequence).ok_or_else(|| {
            ConsoleError::Operation("execution cleanup owner is unavailable".into())
        })?;
        if record.reference.process_id != ticket.process().get().to_string() {
            return Err(ConsoleError::Operation(
                "cleanup ticket belongs to another execution process".into(),
            ));
        }
        if record.custody_pending() {
            record.cleanup_ticket.get_or_insert(ticket);
        }
        Ok(())
    }

    pub fn finish(mut self, cleanup_complete: bool) {
        self.settle(cleanup_complete);
    }

    /// Confirm the lifecycle after an earlier body-release observation. The
    /// original body result and its retention deadline remain unchanged.
    pub(crate) fn record_terminal_outcome(&self, outcome: &'static str) {
        if let Some(record) = self.registry.records().entries.get_mut(&self.sequence) {
            let completion = match &mut record.phase {
                Phase::Running { completion, .. } => completion.as_mut(),
                Phase::Finished { completion, .. } => Some(completion),
            };
            if let Some(completion) = completion {
                completion.outcome = outcome.into();
            }
            if let Some(output) = &mut record.output {
                output.update_terminal_outcome(outcome);
            }
        }
    }

    /// Idempotently acknowledge cleanup without renewing the first result's retention.
    pub fn settle(&mut self, cleanup_complete: bool) {
        if self.finished {
            let captured = self.registry.capture_finalization(self.sequence);
            let mut changed = false;
            if let Some(record) = self.registry.records().entries.get_mut(&self.sequence)
                && let Phase::Finished { completion, .. } = &mut record.phase
            {
                if let Some(captured) = captured {
                    completion.retain_finalization(&captured);
                    changed = cleanup_complete && captured.complete && !completion.cleanup_complete;
                    completion.cleanup_complete |= cleanup_complete && captured.complete;
                    if let Some(output) = &mut record.output {
                        output.update_finalization(completion);
                    }
                }
                if completion.cleanup_complete {
                    record.cleanup_ticket = None;
                }
            }
            if changed {
                self.registry.changed.notify_waiters();
            }
        } else {
            self.publish(Some(cleanup_complete));
        }
    }

    fn publish(&mut self, finalization: Option<bool>) {
        let captured = self.registry.capture_finalization(self.sequence);
        if let Some(record) = self.registry.records().entries.get_mut(&self.sequence)
            && let Phase::Running { completion, .. } = &mut record.phase
        {
            // Take the body result and publish its terminal record under one lock;
            // concurrent observers must never see finalizing revert to running.
            let mut completion = completion.take().unwrap_or(Completion {
                outcome: "interrupted".into(),
                stop_cause: None,
                result: RetainedResult::Omitted("worker stopped; effects may have occurred".into()),
                unresolved_operations: xolotl_types::UnresolvedOperations {
                    identities_incomplete: true,
                    ..Default::default()
                },
                cleanup_complete: false,
                finalization: finalization::FinalizationProjection::Pending,
            });
            if let Some(captured) = captured {
                completion.retain_finalization(&captured);
                completion.cleanup_complete = finalization == Some(true) && captured.complete;
            }
            if completion.cleanup_complete {
                record.cleanup_ticket = None;
            }
            let finished_at = self
                .registry
                .host_runtime
                .now_millis()
                .max(record.created_at);
            if let Some(output) = &mut record.output {
                output.seal(&completion);
            }
            record.phase = Phase::Finished {
                completion,
                expires: self
                    .registry
                    .host_runtime
                    .deadline_after(Duration::from_millis(self.registry.config.retention_ms))
                    .unwrap_or_else(|| self.registry.host_runtime.now()),
                finished_at,
                expires_at: finished_at.saturating_add(self.registry.config.retention_ms as i64),
            };
        }
        self.finished = true;
        self.registry.changed.notify_waiters();
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if !self.finished {
            self.publish(None);
        }
    }
}
