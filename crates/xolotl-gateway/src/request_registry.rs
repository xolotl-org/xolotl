//! In-flight request accounting, bounded cancellation history, and lease-owned cleanup.

use parking_lot::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use xolotl_kernel::{
    Bootstrap, RequestProcess,
    host::{AbortTask, HostDeadline, HostRuntime},
};
use xolotl_types::{ExecutionOutput, Failure, Outcome, ProcessId};

use crate::{
    GatewayAccepted, GatewayBudgetProfile, GatewayCancelRequest, GatewayError, GatewayLimitProfile,
    GatewayProfileRev, GatewaySession, maintenance_health::MaintenanceTracker, random_gateway_id,
};

pub(super) const COMPLETED_REQUEST_RETENTION: Duration = Duration::from_secs(60);
const DEADLINE_SWEEP_INTERVAL_MS: u64 = 50;

/// Runtime state tracked for a Gateway request registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GatewayRequestState {
    Running,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

/// In-memory request entry retained while execution or output owns its lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GatewayRequestEntry {
    pub(super) accepted: GatewayAccepted,
    pub(super) request_process: ProcessId,
    pub(super) gateway_id: String,
    pub(super) principal_id: String,
    pub(super) state: GatewayRequestState,
    pub(super) deadline: Option<HostDeadline>,
    pub(super) cancelled_until: Option<HostDeadline>,
}

/// Only cancelled requests need a short history after the last lease owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GatewayRequestHistoryEntry {
    gateway_id: String,
    principal_id: String,
    trace_root: String,
}

pub(super) struct GatewayRequestRegistry {
    pub(super) inner: Mutex<GatewayRequestRegistryInner>,
    pub(super) host: HostRuntime,
    pub(super) clock_epoch: HostDeadline,
}

impl std::fmt::Debug for GatewayRequestRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayRequestRegistry")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub(super) struct GatewayRequestRegistryInner {
    /// Full entries exist only while their request lease is owned.
    pub(super) entries: BTreeMap<String, GatewayRequestEntry>,
    /// Active request deadlines ordered by their offset in this runtime's
    /// monotonic clock domain. The value set supports removal by borrowed id.
    pub(super) deadlines: BTreeMap<Duration, BTreeSet<String>>,
    pub(super) history: BTreeMap<String, GatewayRequestHistoryEntry>,
    /// Monotonic offsets from the registry epoch, preserving cancellation
    /// expiry order even when leases are released out of order.
    pub(super) history_expirations: BTreeSet<(Duration, u64, String)>,
    next_history_sequence: u64,
    max_recent_cancellations: usize,
    pub(super) global_running: usize,
    pub(super) principal_running: BTreeMap<String, usize>,
    pub(super) surface_running: BTreeMap<String, usize>,
    pub(super) risk_running: BTreeMap<String, usize>,
    pub(super) budget_running: GatewayBudgetCharge,
    pub(super) budget_reservations: BTreeMap<u64, GatewayBudgetCharge>,
    next_budget_reservation_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GatewayExpiredRequest {
    pub(super) request_process: ProcessId,
}

pub(super) struct GatewayDeadlineSweep {
    pub(super) expired_requests: usize,
    pub(super) failed_cancellations: usize,
}

#[derive(Debug)]
pub(super) struct GatewayAdmissionGuard {
    registry: Arc<GatewayRequestRegistry>,
    principal_id: String,
    surface_ids: Vec<String>,
    risk_class: String,
    released: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct GatewayBudgetCharge {
    pub(super) inflight_ops: u64,
    pub(super) wall_ms: u64,
    pub(super) bytes_in: u64,
    pub(super) bytes_out: u64,
    pub(super) inline_value_bytes: u64,
    pub(super) stream_items: u64,
    pub(super) estimated_cost_micro_usd: u64,
}

#[derive(Debug)]
pub(super) struct GatewayBudgetGuard {
    registry: Arc<GatewayRequestRegistry>,
    reservation_id: u64,
    released: bool,
}

#[derive(Debug)]
pub(super) struct GatewayRequestLease {
    pub(super) delivery: Arc<crate::GatewaySubmissionAuthority>,
    pub(super) registry: Arc<GatewayRequestRegistry>,
    pub(super) submission_id: String,
    admission: GatewayAdmissionGuard,
    budget: GatewayBudgetGuard,
}

#[derive(Debug)]
pub(super) struct GatewayRequestGuard {
    pub(super) lease: Arc<GatewayRequestLease>,
    pub(super) process: Option<RequestProcess<'static>>,
    finished: bool,
}

impl GatewayRequestRegistry {
    pub(super) fn new(max_recent_cancellations: usize, host: HostRuntime) -> Self {
        let clock_epoch = host.now();
        Self {
            inner: Mutex::new(GatewayRequestRegistryInner {
                max_recent_cancellations,
                ..GatewayRequestRegistryInner::default()
            }),
            host,
            clock_epoch,
        }
    }

    pub(super) fn set_history_limit(&self, max_recent_cancellations: usize) {
        let mut inner = self.inner.lock();
        inner.max_recent_cancellations = max_recent_cancellations;
        prune_request_history(&mut inner, self.host.now(), self.clock_epoch);
    }

    pub(super) fn new_acceptance(
        &self,
        profile_rev: GatewayProfileRev,
        surface_id: String,
    ) -> Result<GatewayAccepted, GatewayError> {
        for _ in 0..8 {
            let accepted = GatewayAccepted {
                submission_id: random_gateway_id("gw-submission", profile_rev)?,
                trace_root: random_gateway_id("gw-trace", profile_rev)?,
                profile_rev,
                surface_id: surface_id.clone(),
            };
            let inner = self.inner.lock();
            if !inner.entries.contains_key(&accepted.submission_id)
                && !inner.history.contains_key(&accepted.submission_id)
            {
                return Ok(accepted);
            }
        }
        Err(GatewayError::LimitExceeded(
            "submission id collision retry limit exceeded".into(),
        ))
    }

    pub(super) fn try_reserve_budget(
        self: &Arc<Self>,
        budget: &GatewayBudgetProfile,
        charge: GatewayBudgetCharge,
    ) -> Result<GatewayBudgetGuard, GatewayError> {
        let mut inner = self.inner.lock();
        ensure_budget_capacity(
            budget.max_inflight_ops,
            inner.budget_running.inflight_ops,
            charge.inflight_ops,
            "gateway budget in-flight ops",
        )?;
        ensure_budget_capacity(
            budget.max_wall_ms,
            inner.budget_running.wall_ms,
            charge.wall_ms,
            "gateway budget wall-ms",
        )?;
        ensure_budget_capacity(
            budget.max_bytes_in,
            inner.budget_running.bytes_in,
            charge.bytes_in,
            "gateway budget bytes-in",
        )?;
        ensure_budget_capacity(
            budget.max_bytes_out,
            inner.budget_running.bytes_out,
            charge.bytes_out,
            "gateway budget bytes-out",
        )?;
        ensure_budget_capacity(
            budget.max_inline_value_bytes,
            inner.budget_running.inline_value_bytes,
            charge.inline_value_bytes,
            "gateway budget inline value bytes",
        )?;
        ensure_budget_capacity(
            budget.max_stream_items,
            inner.budget_running.stream_items,
            charge.stream_items,
            "gateway budget stream items",
        )?;
        ensure_budget_capacity(
            budget.max_estimated_cost_micro_usd,
            inner.budget_running.estimated_cost_micro_usd,
            charge.estimated_cost_micro_usd,
            "gateway budget estimated cost",
        )?;

        inner.next_budget_reservation_id = inner.next_budget_reservation_id.saturating_add(1);
        let reservation_id = inner.next_budget_reservation_id;
        inner.budget_running = add_budget_charge(inner.budget_running, charge);
        inner.budget_reservations.insert(reservation_id, charge);
        Ok(GatewayBudgetGuard {
            registry: self.clone(),
            reservation_id,
            released: false,
        })
    }

    pub(super) fn try_admit(
        self: &Arc<Self>,
        limits: &GatewayLimitProfile,
        principal_id: String,
        surface_ids: Vec<String>,
        risk_class: String,
    ) -> Result<GatewayAdmissionGuard, GatewayError> {
        let mut inner = self.inner.lock();
        if inner.global_running >= limits.max_in_flight_requests {
            return Err(GatewayError::LimitExceeded(
                "global in-flight request limit".into(),
            ));
        }
        let principal_limit = effective_fair_counter_limit(
            limits.max_principal_in_flight_requests,
            limits.max_in_flight_requests,
        );
        if counter_value(&inner.principal_running, &principal_id) >= principal_limit {
            return Err(GatewayError::LimitExceeded(
                "principal in-flight request limit".into(),
            ));
        }
        let surface_limit = effective_fair_counter_limit(
            limits.max_surface_in_flight_requests,
            limits.max_in_flight_requests,
        );
        for surface_id in &surface_ids {
            if counter_value(&inner.surface_running, surface_id) >= surface_limit {
                return Err(GatewayError::LimitExceeded(
                    "surface in-flight request limit".into(),
                ));
            }
        }
        let risk_limit = effective_fair_counter_limit(
            limits.max_risk_class_in_flight_requests,
            limits.max_in_flight_requests,
        );
        if counter_value(&inner.risk_running, &risk_class) >= risk_limit {
            return Err(GatewayError::LimitExceeded(
                "risk-class in-flight request limit".into(),
            ));
        }

        inner.global_running = inner.global_running.saturating_add(1);
        increment_counter(&mut inner.principal_running, &principal_id);
        for surface_id in &surface_ids {
            increment_counter(&mut inner.surface_running, surface_id);
        }
        increment_counter(&mut inner.risk_running, &risk_class);

        Ok(GatewayAdmissionGuard {
            registry: self.clone(),
            principal_id,
            surface_ids,
            risk_class,
            released: false,
        })
    }

    pub(super) fn insert_running(
        self: &Arc<Self>,
        entry: GatewayRequestEntry,
        admission: GatewayAdmissionGuard,
        budget: GatewayBudgetGuard,
        process: RequestProcess<'static>,
        delivery: Arc<crate::GatewaySubmissionAuthority>,
    ) -> Result<GatewayRequestGuard, GatewayError> {
        let submission_id = entry.accepted.submission_id.clone();
        let deadline_offset = entry
            .deadline
            .map(|deadline| {
                self.host
                    .validate_deadline(deadline)
                    .and_then(|()| deadline.saturating_duration_since(self.clock_epoch))
                    .map_err(|error| GatewayError::Rejected(error.to_string()))
            })
            .transpose()?;
        let mut inner = self.inner.lock();
        prune_request_history(&mut inner, self.host.now(), self.clock_epoch);
        if inner.entries.contains_key(&submission_id) || inner.history.contains_key(&submission_id)
        {
            return Err(GatewayError::LimitExceeded(
                "submission id collision".into(),
            ));
        }
        if let Some(offset) = deadline_offset {
            inner
                .deadlines
                .entry(offset)
                .or_default()
                .insert(submission_id.clone());
        }
        inner.entries.insert(submission_id.clone(), entry);
        Ok(GatewayRequestGuard {
            lease: Arc::new(GatewayRequestLease {
                delivery,
                registry: self.clone(),
                submission_id,
                admission,
                budget,
            }),
            process: Some(process),
            finished: false,
        })
    }

    fn finish(&self, submission_id: &str, state: GatewayRequestState) {
        let mut inner = self.inner.lock();
        let now = self.host.now();
        if let Some(entry) = inner.entries.get_mut(submission_id)
            && entry.state == GatewayRequestState::Running
        {
            entry.state = state;
            if state == GatewayRequestState::Cancelled {
                entry.cancelled_until = now.checked_add(COMPLETED_REQUEST_RETENTION);
            }
            if let Some(deadline) = entry.deadline {
                remove_deadline_index(&mut inner, submission_id, deadline, self.clock_epoch);
            }
        }
        prune_request_history(&mut inner, now, self.clock_epoch);
    }

    pub(super) fn cancel(
        &self,
        session: &GatewaySession,
        request: &GatewayCancelRequest,
        boot: &Bootstrap,
    ) -> Result<bool, GatewayError> {
        if request.submission_id.trim().is_empty() || request.trace_root.trim().is_empty() {
            return Ok(false);
        }
        let process = {
            let mut inner = self.inner.lock();
            let now = self.host.now();
            prune_request_history(&mut inner, now, self.clock_epoch);
            let Some(entry) = inner.entries.get_mut(&request.submission_id) else {
                return Ok(inner
                    .history
                    .get(&request.submission_id)
                    .is_some_and(|entry| {
                        entry.gateway_id == session.profile_name
                            && entry.principal_id == session.principal.principal_id
                            && entry.trace_root == request.trace_root
                    }));
            };
            if entry.principal_id != session.principal.principal_id
                || entry.gateway_id != session.profile_name
                || entry.accepted.trace_root != request.trace_root
            {
                return Ok(false);
            }
            if entry.state != GatewayRequestState::Running {
                return Ok(matches!(entry.state, GatewayRequestState::Cancelled));
            }
            entry.state = GatewayRequestState::Cancelled;
            entry.cancelled_until = now.checked_add(COMPLETED_REQUEST_RETENTION);
            let process = entry.request_process;
            if let Some(deadline) = entry.deadline {
                remove_deadline_index(
                    &mut inner,
                    &request.submission_id,
                    deadline,
                    self.clock_epoch,
                );
            }
            process
        };
        boot.cancel_process(process)
            .map_err(|error| GatewayError::Rejected(error.to_string()))?;
        Ok(true)
    }

    fn release_admission(&self, admission: &GatewayAdmissionGuard) {
        let mut inner = self.inner.lock();
        decrement_admission_counters(
            &mut inner,
            &admission.principal_id,
            &admission.surface_ids,
            &admission.risk_class,
        );
    }

    fn release_entry_admission(&self, submission_id: &str, admission: &GatewayAdmissionGuard) {
        let mut inner = self.inner.lock();
        let now = self.host.now();
        if let Some((submission_id, entry)) = inner.entries.remove_entry(submission_id) {
            if let Some(deadline) = entry.deadline {
                remove_deadline_index(&mut inner, &submission_id, deadline, self.clock_epoch);
            }
            retain_request_history(&mut inner, submission_id, entry, now, self.clock_epoch);
        }
        decrement_admission_counters(
            &mut inner,
            &admission.principal_id,
            &admission.surface_ids,
            &admission.risk_class,
        );
    }

    fn release_budget(&self, reservation_id: u64) {
        let mut inner = self.inner.lock();
        release_budget_reservation(&mut inner, reservation_id);
    }

    pub(super) fn expire_deadlines(&self, now: HostDeadline) -> Vec<GatewayExpiredRequest> {
        let mut inner = self.inner.lock();
        let mut expired = Vec::new();
        let now_offset = match now.saturating_duration_since(self.clock_epoch) {
            Ok(offset) => offset,
            Err(error) => {
                // A foreign timestamp cannot safely defer a cancellation.
                tracing::error!(%error, "request deadline sweep used a foreign clock domain");
                Duration::MAX
            }
        };
        while inner
            .deadlines
            .first_key_value()
            .is_some_and(|(offset, _)| *offset <= now_offset)
        {
            let Some((_, submission_ids)) = inner.deadlines.pop_first() else {
                break;
            };
            for submission_id in submission_ids {
                if let Some(entry) = inner.entries.get_mut(&submission_id)
                    && entry.state == GatewayRequestState::Running
                {
                    entry.state = GatewayRequestState::Expired;
                    expired.push(GatewayExpiredRequest {
                        request_process: entry.request_process,
                    });
                }
            }
        }
        prune_request_history(&mut inner, now, self.clock_epoch);
        expired
    }
}

impl GatewayAdmissionGuard {
    pub(super) fn belongs_to(&self, registry: &Arc<GatewayRequestRegistry>) -> bool {
        Arc::ptr_eq(&self.registry, registry)
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        self.registry.release_admission(self);
        self.released = true;
    }

    fn release_for_submission(&mut self, submission_id: &str) {
        if self.released {
            return;
        }
        self.registry.release_entry_admission(submission_id, self);
        self.released = true;
    }
}

impl Drop for GatewayAdmissionGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl GatewayBudgetGuard {
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.registry.release_budget(self.reservation_id);
        self.released = true;
    }
}

impl Drop for GatewayBudgetGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl GatewayRequestLease {
    pub(super) fn state(&self) -> Option<GatewayRequestState> {
        let inner = self.registry.inner.lock();
        inner
            .entries
            .get(&self.submission_id)
            .map(|entry| entry.state)
    }

    pub(super) fn output_interruption(&self) -> Option<Failure> {
        match self.state() {
            Some(GatewayRequestState::Cancelled) | None => Some(Failure::Cancelled),
            Some(GatewayRequestState::Expired) => Some(Failure::Timeout),
            Some(
                GatewayRequestState::Running
                | GatewayRequestState::Completed
                | GatewayRequestState::Failed,
            ) => None,
        }
    }

    /// Freeze execution's result before asynchronous persistence and cleanup.
    pub(super) fn finish_execution(&self, output: &mut ExecutionOutput, boot: &Bootstrap) {
        let now = self.registry.host.now();
        let expired_process = {
            let mut inner = self.registry.inner.lock();
            let Some(entry) = inner.entries.get_mut(&self.submission_id) else {
                output.outcome = Outcome::Fail(Failure::Cancelled);
                return;
            };
            let mut remove_deadline = None;
            if entry.state == GatewayRequestState::Running {
                remove_deadline = entry.deadline;
                entry.state = if entry
                    .deadline
                    .is_some_and(|deadline| deadline.elapsed_at(now).unwrap_or(true))
                {
                    GatewayRequestState::Expired
                } else {
                    match output.outcome {
                        Outcome::Done(_) | Outcome::Short(_) => GatewayRequestState::Completed,
                        Outcome::Fail(_) => GatewayRequestState::Failed,
                    }
                };
            }
            let expired_process = match entry.state {
                GatewayRequestState::Cancelled => {
                    output.outcome = Outcome::Fail(Failure::Cancelled);
                    None
                }
                GatewayRequestState::Expired => {
                    output.outcome = Outcome::Fail(Failure::Timeout);
                    Some(entry.request_process)
                }
                GatewayRequestState::Running
                | GatewayRequestState::Completed
                | GatewayRequestState::Failed => None,
            };
            if let Some(deadline) = remove_deadline {
                remove_deadline_index(
                    &mut inner,
                    &self.submission_id,
                    deadline,
                    self.registry.clock_epoch,
                );
            }
            prune_request_history(&mut inner, now, self.registry.clock_epoch);
            expired_process
        };
        if let Some(process) = expired_process
            && let Err(error) = boot.cancel_process(process)
        {
            tracing::error!(
                process = process.get(),
                error = %error,
                "request deadline cancellation failed"
            );
        }
    }
}

impl Drop for GatewayRequestLease {
    fn drop(&mut self) {
        self.admission.release_for_submission(&self.submission_id);
        self.budget.release();
    }
}

impl GatewayRequestGuard {
    pub(super) fn finish(&mut self) -> Result<(), GatewayError> {
        let process = self.process.as_ref().ok_or_else(|| {
            GatewayError::Indeterminate(
                "request cleanup owner is missing before acknowledgement".into(),
            )
        })?;
        let ticket = process.cleanup_ticket();
        if !ticket.is_complete() || ticket.finalization_report().is_none() {
            return Err(GatewayError::Indeterminate(
                "request cleanup cannot be acknowledged without completed custody and its report"
                    .into(),
            ));
        }
        self.finished = true;
        if let Some(process) = self.process.take() {
            process.detach();
        }
        Ok(())
    }

    pub(super) fn fail(&mut self) {
        self.lease
            .registry
            .finish(&self.lease.submission_id, GatewayRequestState::Failed);
        self.finished = true;
        drop(self.process.take());
    }
}

impl Drop for GatewayRequestGuard {
    fn drop(&mut self) {
        if !self.finished {
            // Abandoning execution interrupts borrowed output too. A driver's
            // ordinary failure is still deliverable, so it is a different state.
            // `finish` preserves results already frozen before persistence.
            self.lease
                .registry
                .finish(&self.lease.submission_id, GatewayRequestState::Cancelled);
        }
        drop(self.process.take());
    }
}

fn effective_fair_counter_limit(configured_limit: usize, global_limit: usize) -> usize {
    configured_limit.min(fair_counter_limit(global_limit))
}

fn fair_counter_limit(global_limit: usize) -> usize {
    match global_limit {
        0 | 1 => global_limit,
        n => n.saturating_sub(1).max(1),
    }
}

fn counter_value(map: &BTreeMap<String, usize>, key: &str) -> usize {
    map.get(key).copied().unwrap_or(0)
}

fn increment_counter(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

fn decrement_counter(map: &mut BTreeMap<String, usize>, key: &str) {
    let Some(count) = map.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        map.remove(key);
    }
}

fn decrement_admission_counters(
    inner: &mut GatewayRequestRegistryInner,
    principal_id: &str,
    surface_ids: &[String],
    risk_class: &str,
) {
    inner.global_running = inner.global_running.saturating_sub(1);
    decrement_counter(&mut inner.principal_running, principal_id);
    for surface_id in surface_ids {
        decrement_counter(&mut inner.surface_running, surface_id);
    }
    decrement_counter(&mut inner.risk_running, risk_class);
}

fn remove_deadline_index(
    inner: &mut GatewayRequestRegistryInner,
    submission_id: &str,
    deadline: HostDeadline,
    epoch: HostDeadline,
) {
    let Ok(offset) = deadline.saturating_duration_since(epoch) else {
        // The entry and index should share the registry clock. If that
        // invariant is broken, still remove every key for this request.
        tracing::error!(submission_id, "request deadline has a foreign clock domain");
        inner.deadlines.retain(|_, ids| {
            ids.remove(submission_id);
            !ids.is_empty()
        });
        return;
    };
    let Some(ids) = inner.deadlines.get_mut(&offset) else {
        return;
    };
    ids.remove(submission_id);
    if ids.is_empty() {
        inner.deadlines.remove(&offset);
    }
}

fn release_budget_reservation(
    inner: &mut GatewayRequestRegistryInner,
    reservation_id: u64,
) -> bool {
    let Some(charge) = inner.budget_reservations.remove(&reservation_id) else {
        return false;
    };
    inner.budget_running = subtract_budget_charge(inner.budget_running, charge);
    true
}

fn ensure_budget_capacity(
    limit: Option<u64>,
    current: u64,
    charge: u64,
    label: &'static str,
) -> Result<(), GatewayError> {
    let Some(limit) = limit else {
        return Ok(());
    };
    if current.saturating_add(charge) > limit {
        return Err(GatewayError::LimitExceeded(format!("{label} limit")));
    }
    Ok(())
}

fn add_budget_charge(left: GatewayBudgetCharge, right: GatewayBudgetCharge) -> GatewayBudgetCharge {
    GatewayBudgetCharge {
        inflight_ops: left.inflight_ops.saturating_add(right.inflight_ops),
        wall_ms: left.wall_ms.saturating_add(right.wall_ms),
        bytes_in: left.bytes_in.saturating_add(right.bytes_in),
        bytes_out: left.bytes_out.saturating_add(right.bytes_out),
        inline_value_bytes: left
            .inline_value_bytes
            .saturating_add(right.inline_value_bytes),
        stream_items: left.stream_items.saturating_add(right.stream_items),
        estimated_cost_micro_usd: left
            .estimated_cost_micro_usd
            .saturating_add(right.estimated_cost_micro_usd),
    }
}

fn subtract_budget_charge(
    left: GatewayBudgetCharge,
    right: GatewayBudgetCharge,
) -> GatewayBudgetCharge {
    GatewayBudgetCharge {
        inflight_ops: left.inflight_ops.saturating_sub(right.inflight_ops),
        wall_ms: left.wall_ms.saturating_sub(right.wall_ms),
        bytes_in: left.bytes_in.saturating_sub(right.bytes_in),
        bytes_out: left.bytes_out.saturating_sub(right.bytes_out),
        inline_value_bytes: left
            .inline_value_bytes
            .saturating_sub(right.inline_value_bytes),
        stream_items: left.stream_items.saturating_sub(right.stream_items),
        estimated_cost_micro_usd: left
            .estimated_cost_micro_usd
            .saturating_sub(right.estimated_cost_micro_usd),
    }
}

fn retain_request_history(
    inner: &mut GatewayRequestRegistryInner,
    submission_id: String,
    entry: GatewayRequestEntry,
    now: HostDeadline,
    epoch: HostDeadline,
) {
    if entry.state != GatewayRequestState::Cancelled || inner.max_recent_cancellations == 0 {
        return;
    }
    let Some(expires) = entry
        .cancelled_until
        .filter(|expires| expires.elapsed_at(now) == Ok(false))
    else {
        return;
    };
    let Ok(offset) = expires.saturating_duration_since(epoch) else {
        tracing::error!("cancellation history deadline has a foreign clock domain");
        return;
    };
    inner.history.insert(
        submission_id.clone(),
        GatewayRequestHistoryEntry {
            gateway_id: entry.gateway_id,
            principal_id: entry.principal_id,
            trace_root: entry.accepted.trace_root,
        },
    );
    let sequence = inner.next_history_sequence;
    inner.next_history_sequence = sequence.saturating_add(1);
    inner
        .history_expirations
        .insert((offset, sequence, submission_id));
    prune_request_history(inner, now, epoch);
}

pub(super) fn prune_request_history(
    inner: &mut GatewayRequestRegistryInner,
    now: HostDeadline,
    epoch: HostDeadline,
) {
    let now_offset = match now.saturating_duration_since(epoch) {
        Ok(offset) => offset,
        Err(error) => {
            tracing::error!(%error, "cancellation history sweep used a foreign clock domain");
            Duration::MAX
        }
    };
    while inner
        .history_expirations
        .first()
        .is_some_and(|(expires, _, _)| {
            *expires <= now_offset || inner.history.len() > inner.max_recent_cancellations
        })
    {
        let Some((_, _, submission_id)) = inner.history_expirations.pop_first() else {
            break;
        };
        inner.history.remove(&submission_id);
    }
}

pub(super) fn sweep_expired_requests(
    boot: &Bootstrap,
    registry: &GatewayRequestRegistry,
) -> GatewayDeadlineSweep {
    let expired = registry.expire_deadlines(registry.host.now());
    let mut failed_cancellations = 0;
    for request in &expired {
        if let Err(error) = boot.cancel_process(request.request_process) {
            failed_cancellations += 1;
            tracing::error!(
                process = request.request_process.get(),
                error = %error,
                "deadline sweep failed to cancel request process"
            );
        }
    }
    GatewayDeadlineSweep {
        expired_requests: expired.len(),
        failed_cancellations,
    }
}

pub(super) fn spawn_deadline_sweeper(
    boot: &Arc<Bootstrap>,
    registry: &Arc<GatewayRequestRegistry>,
) -> Result<(Arc<dyn AbortTask>, MaintenanceTracker), GatewayError> {
    let host = boot.kernel().host_runtime().clone();
    let started = host.now();
    let first_tick = started
        .checked_add(Duration::from_millis(DEADLINE_SWEEP_INTERVAL_MS))
        .ok_or_else(|| {
            GatewayError::Rejected("gateway request maintenance deadline is out of range".into())
        })?;
    let boot = Arc::downgrade(boot);
    let registry = Arc::downgrade(registry);
    let (tracker, exit) = MaintenanceTracker::owned(started);
    let task_tracker = tracker.clone();
    let task = host
        .clone()
        .spawn(Box::pin(async move {
            let _exit = exit;
            let mut next_tick = first_tick;
            loop {
                if let Err(error) = host.sleep_until(next_tick).await {
                    tracing::error!(%error, "gateway request maintenance clock domain changed");
                    break;
                }
                let (Some(boot), Some(registry)) = (boot.upgrade(), registry.upgrade()) else {
                    break;
                };
                let pass = task_tracker.begin(host.now());
                let sweep = sweep_expired_requests(&boot, &registry);
                pass.complete(host.now(), sweep.failed_cancellations == 0);
                let Some(deadline) =
                    host.deadline_after(Duration::from_millis(DEADLINE_SWEEP_INTERVAL_MS))
                else {
                    tracing::error!("gateway request maintenance deadline is out of range");
                    break;
                };
                next_tick = deadline;
            }
        }))
        .map_err(|error| {
            GatewayError::Rejected(format!(
                "gateway request deadline maintenance requires host task scheduler: {error}"
            ))
        })?;
    Ok((task, tracker))
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicI64, AtomicU64, Ordering},
        time::Instant,
    };
    use xolotl_kernel::host::{
        AbortTask, HostClock, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
    };

    struct Clock {
        base: Instant,
        monotonic_ms: AtomicU64,
        wall_ms: AtomicI64,
    }

    impl HostClock for Clock {
        fn monotonic_now(&self) -> Instant {
            self.base + Duration::from_millis(self.monotonic_ms.load(Ordering::SeqCst))
        }

        fn unix_millis(&self) -> i64 {
            self.wall_ms.load(Ordering::SeqCst)
        }

        fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    #[test]
    fn request_deadlines_use_host_monotonic_time_even_if_wall_clock_moves() -> anyhow::Result<()> {
        let clock = Arc::new(Clock {
            base: Instant::now(),
            monotonic_ms: AtomicU64::new(0),
            wall_ms: AtomicI64::new(1_000),
        });
        let host = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(TokioBlockingSpawner::default()),
        );
        let registry = GatewayRequestRegistry::new(4, host.clone());
        let deadline = host
            .deadline_after(Duration::from_millis(10))
            .ok_or_else(|| anyhow::anyhow!("host deadline overflow"))?;
        let id = "submission".to_string();
        {
            let mut inner = registry.inner.lock();
            inner.entries.insert(
                id.clone(),
                GatewayRequestEntry {
                    accepted: GatewayAccepted {
                        submission_id: id.clone(),
                        trace_root: "trace".into(),
                        profile_rev: 1,
                        surface_id: "surface".into(),
                    },
                    request_process: ProcessId::new(7),
                    gateway_id: "gateway".into(),
                    principal_id: "principal".into(),
                    state: GatewayRequestState::Running,
                    deadline: Some(deadline),
                    cancelled_until: None,
                },
            );
            let offset = deadline.saturating_duration_since(registry.clock_epoch)?;
            inner
                .deadlines
                .entry(offset)
                .or_default()
                .insert(id.clone());
        }

        clock.wall_ms.store(100_000, Ordering::SeqCst);
        anyhow::ensure!(registry.expire_deadlines(host.now()).is_empty());
        clock.wall_ms.store(-100_000, Ordering::SeqCst);
        clock.monotonic_ms.store(10, Ordering::SeqCst);
        anyhow::ensure!(
            registry.expire_deadlines(host.now())
                == vec![GatewayExpiredRequest {
                    request_process: ProcessId::new(7)
                }]
        );
        anyhow::ensure!(registry.expire_deadlines(host.now()).is_empty());
        let inner = registry.inner.lock();
        anyhow::ensure!(
            inner.entries.get(&id).map(|entry| entry.state) == Some(GatewayRequestState::Expired)
        );
        anyhow::ensure!(inner.deadlines.is_empty());
        Ok(())
    }

    #[test]
    fn deadline_index_expires_only_the_due_prefix_in_deadline_order() -> anyhow::Result<()> {
        let clock = Arc::new(Clock {
            base: Instant::now(),
            monotonic_ms: AtomicU64::new(0),
            wall_ms: AtomicI64::new(1_000),
        });
        let host = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(TokioBlockingSpawner::default()),
        );
        let registry = GatewayRequestRegistry::new(4, host.clone());
        // Insert out of deadline order, including two requests in one bucket.
        for (id, process, delay_ms) in [
            ("late", 3, 30),
            ("early-b", 4, 10),
            ("middle", 2, 20),
            ("early-a", 1, 10),
        ] {
            let deadline = host
                .deadline_after(Duration::from_millis(delay_ms))
                .ok_or_else(|| anyhow::anyhow!("test deadline overflow"))?;
            let offset = deadline.saturating_duration_since(registry.clock_epoch)?;
            let mut inner = registry.inner.lock();
            inner.entries.insert(
                id.into(),
                GatewayRequestEntry {
                    accepted: GatewayAccepted {
                        submission_id: id.into(),
                        trace_root: "trace".into(),
                        profile_rev: 1,
                        surface_id: "surface".into(),
                    },
                    request_process: ProcessId::new(process),
                    gateway_id: "gateway".into(),
                    principal_id: "principal".into(),
                    state: GatewayRequestState::Running,
                    deadline: Some(deadline),
                    cancelled_until: None,
                },
            );
            inner.deadlines.entry(offset).or_default().insert(id.into());
        }
        clock.monotonic_ms.store(5, Ordering::SeqCst);
        for _ in 0..3 {
            anyhow::ensure!(registry.expire_deadlines(host.now()).is_empty());
        }
        anyhow::ensure!(registry.inner.lock().deadlines.len() == 3);

        clock.monotonic_ms.store(10, Ordering::SeqCst);
        anyhow::ensure!(
            registry.expire_deadlines(host.now())
                == vec![
                    GatewayExpiredRequest {
                        request_process: ProcessId::new(1),
                    },
                    GatewayExpiredRequest {
                        request_process: ProcessId::new(4),
                    },
                ]
        );
        anyhow::ensure!(registry.inner.lock().deadlines.len() == 2);
        clock.monotonic_ms.store(20, Ordering::SeqCst);
        anyhow::ensure!(
            registry.expire_deadlines(host.now())
                == vec![GatewayExpiredRequest {
                    request_process: ProcessId::new(2),
                }]
        );
        clock.monotonic_ms.store(30, Ordering::SeqCst);
        anyhow::ensure!(
            registry.expire_deadlines(host.now())
                == vec![GatewayExpiredRequest {
                    request_process: ProcessId::new(3),
                }]
        );
        anyhow::ensure!(registry.inner.lock().deadlines.is_empty());
        Ok(())
    }

    #[test]
    fn deadline_index_fails_closed_on_foreign_sweep_clock() -> anyhow::Result<()> {
        let clock = Arc::new(Clock {
            base: Instant::now(),
            monotonic_ms: AtomicU64::new(0),
            wall_ms: AtomicI64::new(1_000),
        });
        let host = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(TokioBlockingSpawner::default()),
        );
        let foreign = HostRuntime::new(
            clock,
            Arc::new(NoTasks),
            Arc::new(TokioBlockingSpawner::default()),
        );
        let registry = GatewayRequestRegistry::new(4, host.clone());
        let deadline = host
            .deadline_after(Duration::from_secs(5))
            .ok_or_else(|| anyhow::anyhow!("test deadline overflow"))?;
        let offset = deadline.saturating_duration_since(registry.clock_epoch)?;
        {
            let mut inner = registry.inner.lock();
            inner.entries.insert(
                "submission".into(),
                GatewayRequestEntry {
                    accepted: GatewayAccepted {
                        submission_id: "submission".into(),
                        trace_root: "trace".into(),
                        profile_rev: 1,
                        surface_id: "surface".into(),
                    },
                    request_process: ProcessId::new(7),
                    gateway_id: "gateway".into(),
                    principal_id: "principal".into(),
                    state: GatewayRequestState::Running,
                    deadline: Some(deadline),
                    cancelled_until: None,
                },
            );
            inner
                .deadlines
                .entry(offset)
                .or_default()
                .insert("submission".into());
        }
        anyhow::ensure!(
            registry.expire_deadlines(foreign.now())
                == vec![GatewayExpiredRequest {
                    request_process: ProcessId::new(7),
                }]
        );
        anyhow::ensure!(registry.inner.lock().deadlines.is_empty());
        Ok(())
    }

    #[test]
    fn cancellation_history_prunes_with_installed_host_monotonic_clock() {
        let clock = Arc::new(Clock {
            base: Instant::now(),
            monotonic_ms: AtomicU64::new(0),
            wall_ms: AtomicI64::new(1_000),
        });
        let host = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(TokioBlockingSpawner::default()),
        );
        let registry = GatewayRequestRegistry::new(4, host);
        {
            let mut inner = registry.inner.lock();
            inner.history.insert(
                "submission".into(),
                GatewayRequestHistoryEntry {
                    gateway_id: "gateway".into(),
                    principal_id: "principal".into(),
                    trace_root: "trace".into(),
                },
            );
            inner
                .history_expirations
                .insert((Duration::from_millis(10), 0, "submission".into()));
        }
        clock.wall_ms.store(100_000, Ordering::SeqCst);
        registry.set_history_limit(4);
        assert_eq!(registry.inner.lock().history.len(), 1);
        clock.wall_ms.store(-100_000, Ordering::SeqCst);
        registry.set_history_limit(4);
        assert_eq!(registry.inner.lock().history.len(), 1);
        clock.monotonic_ms.store(11, Ordering::SeqCst);
        registry.set_history_limit(4);
        assert!(registry.inner.lock().history.is_empty());
    }

    #[test]
    fn cancellation_history_orders_by_decision_deadline_not_lease_release() -> anyhow::Result<()> {
        let clock = Arc::new(Clock {
            base: Instant::now(),
            monotonic_ms: AtomicU64::new(0),
            wall_ms: AtomicI64::new(1_000),
        });
        let host = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(TokioBlockingSpawner::default()),
        );
        let registry = GatewayRequestRegistry::new(4, host.clone());
        let first_expires = host
            .deadline_after(COMPLETED_REQUEST_RETENTION)
            .ok_or_else(|| anyhow::anyhow!("first cancellation deadline overflow"))?;
        clock.monotonic_ms.store(10, Ordering::SeqCst);
        let second_expires = host
            .deadline_after(COMPLETED_REQUEST_RETENTION)
            .ok_or_else(|| anyhow::anyhow!("second cancellation deadline overflow"))?;
        clock.monotonic_ms.store(20, Ordering::SeqCst);
        let mut inner = registry.inner.lock();
        let entry = |id: &str, expires| GatewayRequestEntry {
            accepted: GatewayAccepted {
                submission_id: id.into(),
                trace_root: "trace".into(),
                profile_rev: 1,
                surface_id: "surface".into(),
            },
            request_process: ProcessId::new(7),
            gateway_id: "gateway".into(),
            principal_id: "principal".into(),
            state: GatewayRequestState::Cancelled,
            deadline: None,
            cancelled_until: Some(expires),
        };
        retain_request_history(
            &mut inner,
            "second".into(),
            entry("second", second_expires),
            host.now(),
            registry.clock_epoch,
        );
        retain_request_history(
            &mut inner,
            "first".into(),
            entry("first", first_expires),
            host.now(),
            registry.clock_epoch,
        );
        anyhow::ensure!(
            inner
                .history_expirations
                .first()
                .map(|(_, _, id)| id.as_str())
                == Some("first")
        );
        prune_request_history(&mut inner, first_expires, registry.clock_epoch);
        anyhow::ensure!(!inner.history.contains_key("first"));
        anyhow::ensure!(inner.history.contains_key("second"));
        Ok(())
    }
}
