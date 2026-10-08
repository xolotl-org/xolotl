use anyhow::{Context, Result};
use std::{sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use xolotl_console::{ConsoleService, session_store::ConsoleSessionStore};
use xolotl_kernel::host::{HostDeadline, HostRuntime};

struct RetryEpochSchedule {
    period: Duration,
    deadline: Option<HostDeadline>,
}

impl RetryEpochSchedule {
    fn new(runtime: &HostRuntime, period: Duration, enabled: bool) -> Result<Self> {
        let deadline = if enabled {
            Some(
                runtime
                    .deadline_after(period)
                    .context("Console retry epoch deadline overflow")?,
            )
        } else {
            None
        };
        Ok(Self { period, deadline })
    }

    fn tick(&mut self, runtime: &HostRuntime, rotate: impl FnOnce() -> Result<()>) -> Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let now = runtime.now();
        if !deadline.elapsed_at(now)? {
            return Ok(());
        }
        let next_deadline = now
            .checked_add(self.period)
            .context("Console retry epoch deadline overflow")?;
        rotate()?;
        self.deadline = Some(next_deadline);
        Ok(())
    }
}

pub(super) fn start(
    service: ConsoleService,
    session_store: Arc<dyn ConsoleSessionStore>,
    runtime: HostRuntime,
    retry_epoch_period: Duration,
    retry_enabled: bool,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut schedule = RetryEpochSchedule::new(&runtime, retry_epoch_period, retry_enabled)?;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            schedule.tick(&runtime, || {
                let (_, expected) = service.submission_retry_scope();
                service.close_submission_retry_epoch(expected)?;
                Ok(())
            })?;
            session_store.maintain(runtime.now_millis()).await?;
        }
    })
}

#[cfg(test)]
mod tests;
