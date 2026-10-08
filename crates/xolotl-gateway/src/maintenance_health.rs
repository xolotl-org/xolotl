//! Monotonic progress observations for Gateway maintenance.

use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use xolotl_kernel::host::HostDeadline;

/// Ownership and freshness of one maintenance lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayMaintenanceState {
    /// The host owns the task and its last successful pass is recent.
    Active,
    /// The host owns the task, but no successful pass occurred within its alert window.
    Overdue,
    /// The accepted task exited or was dropped.
    Stopped,
    /// The embedding is responsible for calling `GatewayRuntime::maintain_once`.
    Manual,
    /// State lacks the ports required for bounded object-record cleanup.
    Unavailable,
}

/// Progress measured in the Kernel host's monotonic clock domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayMaintenanceProgress {
    /// Task ownership or manual/unavailable mode.
    pub state: GatewayMaintenanceState,
    /// Time since this Gateway's maintenance tracker was created. This makes a
    /// never-started worker or an idle manual host observable.
    pub observed_for: Duration,
    /// Time since the most recent pass started, if one has started.
    pub since_last_attempt: Option<Duration>,
    /// Time since the most recent fully successful pass, if any.
    pub since_last_success: Option<Duration>,
    /// Passes still in progress, including overlapping manual calls.
    pub active_attempts: usize,
    /// Failed or abandoned passes since the most recent fully successful pass.
    pub consecutive_failures: u64,
}

/// Independently observed request and object-record maintenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayMaintenanceStatus {
    /// Request deadline and cancellation-history sweeps.
    pub request_deadlines: GatewayMaintenanceProgress,
    /// Upload-ticket and object read-grant scans, performed as one pass.
    pub object_records: GatewayMaintenanceProgress,
}

pub(crate) const REQUEST_OVERDUE_AFTER: Duration = Duration::from_secs(1);
pub(crate) const OBJECT_OVERDUE_AFTER: Duration = Duration::from_secs(20);

#[derive(Clone, Copy)]
struct MaintenanceObservation {
    started: HostDeadline,
    last_attempt: Option<HostDeadline>,
    last_success: Option<HostDeadline>,
    active_attempts: usize,
    consecutive_failures: u64,
    alive: bool,
}

/// A pass only takes this small lock at its start and completion. In
/// particular, no State or Kernel I/O holds the observation lock.
#[derive(Clone)]
pub(crate) struct MaintenanceTracker(Arc<Mutex<MaintenanceObservation>>);

/// Settles one pass on completion or cancellation, without holding a lock
/// across the maintenance work.
pub(crate) struct MaintenancePass<'a> {
    tracker: &'a MaintenanceTracker,
    settled: bool,
}

impl MaintenanceTracker {
    pub(crate) fn new(started: HostDeadline) -> Self {
        Self(Arc::new(Mutex::new(MaintenanceObservation {
            started,
            last_attempt: None,
            last_success: None,
            active_attempts: 0,
            consecutive_failures: 0,
            alive: true,
        })))
    }

    pub(crate) fn owned(started: HostDeadline) -> (Self, MaintenanceExit) {
        let tracker = Self::new(started);
        let exit = MaintenanceExit(tracker.clone());
        (tracker, exit)
    }

    pub(crate) fn begin(&self, now: HostDeadline) -> MaintenancePass<'_> {
        let mut state = self.0.lock();
        state.last_attempt = Some(now);
        state.active_attempts = state.active_attempts.saturating_add(1);
        MaintenancePass {
            tracker: self,
            settled: false,
        }
    }

    fn settle(&self, successful_at: Option<HostDeadline>) {
        let mut state = self.0.lock();
        state.active_attempts -= 1;
        if let Some(now) = successful_at {
            state.last_success = Some(now);
            state.consecutive_failures = 0;
        } else {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        }
    }

    fn status(
        &self,
        now: HostDeadline,
        mode: GatewayMaintenanceState,
        overdue_after: Duration,
    ) -> GatewayMaintenanceProgress {
        let observation = *self.0.lock();
        let observed_for = age(now, observation.started);
        let since_last_success = observation.last_success.map(|last| age(now, last));
        let state = if mode == GatewayMaintenanceState::Active {
            if !observation.alive {
                GatewayMaintenanceState::Stopped
            } else if since_last_success.unwrap_or(observed_for) >= overdue_after {
                GatewayMaintenanceState::Overdue
            } else {
                GatewayMaintenanceState::Active
            }
        } else {
            mode
        };
        GatewayMaintenanceProgress {
            state,
            observed_for,
            since_last_attempt: observation.last_attempt.map(|last| age(now, last)),
            since_last_success,
            active_attempts: observation.active_attempts,
            consecutive_failures: observation.consecutive_failures,
        }
    }
}

impl MaintenancePass<'_> {
    pub(crate) fn complete(mut self, now: HostDeadline, success: bool) {
        self.settled = true;
        self.tracker.settle(success.then_some(now));
    }
}

impl Drop for MaintenancePass<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.tracker.settle(None);
        }
    }
}

fn age(now: HostDeadline, earlier: HostDeadline) -> Duration {
    // All observations are made by the same installed HostRuntime. If that
    // invariant breaks, report stale progress instead of reporting health.
    now.saturating_duration_since(earlier)
        .unwrap_or(Duration::MAX)
}

/// Captured before admission: even a never-polled future becomes Stopped when
/// its scheduler releases it.
pub(crate) struct MaintenanceExit(MaintenanceTracker);

impl Drop for MaintenanceExit {
    fn drop(&mut self) {
        self.0.0.lock().alive = false;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MaintenanceMode {
    Manual,
    Automatic,
}

pub(crate) struct MaintenanceHealth {
    mode: MaintenanceMode,
    request_deadlines: MaintenanceTracker,
    object_records: Option<MaintenanceTracker>,
    started: HostDeadline,
}

impl MaintenanceHealth {
    pub(crate) fn manual(started: HostDeadline, object_scans_available: bool) -> MaintenanceHealth {
        Self {
            mode: MaintenanceMode::Manual,
            request_deadlines: MaintenanceTracker::new(started),
            object_records: object_scans_available.then(|| MaintenanceTracker::new(started)),
            started,
        }
    }

    pub(crate) fn automatic(
        started: HostDeadline,
        request_deadlines: MaintenanceTracker,
        object_records: Option<MaintenanceTracker>,
    ) -> MaintenanceHealth {
        Self {
            mode: MaintenanceMode::Automatic,
            request_deadlines,
            object_records,
            started,
        }
    }

    pub(crate) fn manual_request(&self) -> Option<&MaintenanceTracker> {
        if self.mode == MaintenanceMode::Manual {
            Some(&self.request_deadlines)
        } else {
            None
        }
    }

    pub(crate) fn manual_object(&self) -> Option<&MaintenanceTracker> {
        if self.mode == MaintenanceMode::Manual {
            self.object_records.as_ref()
        } else {
            None
        }
    }

    pub(crate) fn status(&self, now: HostDeadline) -> GatewayMaintenanceStatus {
        let unavailable = |started| GatewayMaintenanceProgress {
            state: GatewayMaintenanceState::Unavailable,
            observed_for: age(now, started),
            since_last_attempt: None,
            since_last_success: None,
            active_attempts: 0,
            consecutive_failures: 0,
        };
        let state = match self.mode {
            MaintenanceMode::Manual => GatewayMaintenanceState::Manual,
            MaintenanceMode::Automatic => GatewayMaintenanceState::Active,
        };
        GatewayMaintenanceStatus {
            request_deadlines: self
                .request_deadlines
                .status(now, state, REQUEST_OVERDUE_AFTER),
            object_records: self.object_records.as_ref().map_or_else(
                || unavailable(self.started),
                |tracker| tracker.status(now, state, OBJECT_OVERDUE_AFTER),
            ),
        }
    }
}
