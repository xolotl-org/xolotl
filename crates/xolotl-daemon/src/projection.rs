//! In-process projection reconciliation and status observations.

use super::now_millis;
use anyhow::Result;
use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};
use xolotl_sdk::Bootstrap;
use xolotl_standard::{
    InProcessProjectionInstallEntry, InProcessProjectionInstalled, InstallError, StandardConfig,
    install_declared_in_process_projections, install_in_process_projection_value,
};
use xolotl_state::{StateEvent, StateStream};
use xolotl_types::in_process_projection::{
    IN_PROCESS_PROJECTION_CONFIG_PREFIX, IN_PROCESS_PROJECTION_STATUS_PREFIX,
    in_process_projection_declaration_id, in_process_projection_status_id,
    in_process_projection_status_path,
};
use xolotl_types::{InProcessProjectionPhase, InProcessProjectionStatus, Path};

fn in_process_projection_watch_pattern() -> Result<Path, xolotl_types::PathError> {
    Path::parse(IN_PROCESS_PROJECTION_CONFIG_PREFIX)?.try_push("**")
}

pub(super) async fn start_in_process_projection_reconciler(
    boot: Arc<Bootstrap>,
    config: StandardConfig,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let pattern = in_process_projection_watch_pattern()
        .map_err(|error| anyhow::anyhow!("build in-process projection watch pattern: {error}"))?;
    let events = boot.kernel().state().subscribe(&pattern).await?;
    Ok(tokio::spawn(watch_projections(
        boot, config, pattern, events,
    )))
}

async fn watch_projections(
    boot: Arc<Bootstrap>,
    config: StandardConfig,
    pattern: Path,
    mut events: StateStream,
) -> Result<()> {
    loop {
        match events.recv().await {
            Ok(StateEvent::Set { path, value, .. }) => {
                let id = in_process_projection_declaration_id(&path);
                let result = install_in_process_projection_value(&boot, &path, value, &config);
                if let Err(error) =
                    write_in_process_projection_result_status(&boot, id, &result).await
                {
                    tracing::error!(path = %path, error = %error, "projection status write failed");
                }
                if let Err(error) = result {
                    tracing::error!(
                        path = %path,
                        error = %error,
                        "in-process projection declaration rejected"
                    );
                }
            }
            Ok(StateEvent::Append { path, .. } | StateEvent::DropPrefixAppend { path, .. }) => {
                tracing::error!(
                    path = %path,
                    "in-process projection declaration path received append event"
                );
            }
            Ok(StateEvent::Delete { path, .. }) => {
                if let Err(error) = delete_in_process_projection_status(&boot, &path).await {
                    tracing::error!(
                        path = %path,
                        error = %error,
                        "projection delete status write failed"
                    );
                }
                tracing::error!(
                    path = %path,
                    "in-process projection declaration was deleted; live registry entries remain until restart"
                );
            }
            Err(xolotl_sdk::StateWatchError::Lagged(skipped)) => {
                tracing::error!(
                    skipped,
                    "in-process projection declaration watcher lagged; reconciling declarations"
                );
                retry_projection_operation("reconcile declarations", || {
                    reconcile_declared_projections(&boot, &config)
                })
                .await;
            }
            Err(xolotl_sdk::StateWatchError::Invalidated) => {
                tracing::warn!(
                    "in-process projection declaration watcher invalidated; resubscribing and reconciling"
                );
                events = retry_projection_operation("resubscribe", || async {
                    Ok(boot.kernel().state().subscribe(&pattern).await?)
                })
                .await;
                retry_projection_operation("reconcile declarations", || {
                    reconcile_declared_projections(&boot, &config)
                })
                .await;
            }
            Err(error) => {
                return Err(anyhow::Error::from(error)
                    .context("in-process projection declaration watcher stopped"));
            }
        }
    }
}

async fn reconcile_declared_projections(boot: &Bootstrap, config: &StandardConfig) -> Result<()> {
    let report = install_declared_in_process_projections(boot, config).await?;
    reconcile_in_process_projection_report_status(boot, report.entries).await
}

async fn retry_projection_operation<T, F, Fut>(operation: &'static str, mut attempt: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut delay = Duration::from_millis(100);
    let mut failed = false;
    loop {
        match attempt().await {
            Ok(value) => {
                if failed {
                    tracing::info!(operation, "in-process projection watcher recovered");
                }
                return value;
            }
            Err(error) => {
                if !failed {
                    tracing::error!(operation, %error, "in-process projection watcher recovery failed; retrying");
                    failed = true;
                }
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(5));
            }
        }
    }
}

pub(super) async fn reconcile_in_process_projection_report_status(
    boot: &Bootstrap,
    entries: Vec<InProcessProjectionInstallEntry>,
) -> Result<()> {
    let mut declared_ids = BTreeSet::new();
    for entry in entries {
        let Some(id) = in_process_projection_declaration_id(&entry.path) else {
            tracing::error!(
                path = %entry.path,
                "invalid in-process projection declaration path has no status address"
            );
            continue;
        };
        declared_ids.insert(id.to_string());
        write_in_process_projection_entry_status(boot, entry).await?;
    }
    delete_stale_in_process_projection_statuses(boot, &declared_ids).await?;
    Ok(())
}

async fn write_in_process_projection_entry_status(
    boot: &Bootstrap,
    entry: InProcessProjectionInstallEntry,
) -> Result<()> {
    let status = match entry.result {
        Ok(installed) => active_projection_status(&installed),
        Err(error) => rejected_projection_status(&entry.id, entry.desired.as_ref(), &error),
    };
    write_in_process_projection_status(boot, &status).await
}

async fn write_in_process_projection_result_status(
    boot: &Bootstrap,
    id: Option<&str>,
    result: &Result<InProcessProjectionInstalled, InstallError>,
) -> Result<()> {
    let status = match result {
        Ok(installed) => active_projection_status(installed),
        Err(error) => {
            let Some(id) = id else {
                return Ok(());
            };
            rejected_projection_status(id, None, error)
        }
    };
    write_in_process_projection_status(boot, &status).await
}

async fn delete_in_process_projection_status(
    boot: &Bootstrap,
    declaration_path: &Path,
) -> Result<()> {
    let Some(id) = in_process_projection_declaration_id(declaration_path) else {
        return Ok(());
    };
    let path = in_process_projection_status_path(id)?;
    boot.kernel().state().write_delete(&path).await?;
    Ok(())
}

async fn delete_stale_in_process_projection_statuses(
    boot: &Bootstrap,
    declared_ids: &BTreeSet<String>,
) -> Result<()> {
    let prefix = in_process_projection_status_prefix()?;
    let mut pages = boot
        .kernel()
        .state()
        .pages(xolotl_state::StateScan::new(prefix));
    while let Some(page) = pages.next().await? {
        for (path, _) in page.entries {
            let Some(id) = in_process_projection_status_id(&path) else {
                continue;
            };
            if !declared_ids.contains(id) {
                boot.kernel().state().write_delete(&path).await?;
            }
        }
    }
    Ok(())
}

pub(super) async fn write_in_process_projection_status(
    boot: &Bootstrap,
    status: &InProcessProjectionStatus,
) -> Result<()> {
    let path = in_process_projection_status_path(&status.id)?;
    let value = status.to_value()?;
    boot.kernel().state().write_set(&path, value).await?;
    Ok(())
}

fn active_projection_status(installed: &InProcessProjectionInstalled) -> InProcessProjectionStatus {
    InProcessProjectionStatus {
        id: installed.id.clone(),
        phase: InProcessProjectionPhase::Active,
        implementation: Some(installed.implementation.clone()),
        role: Some(installed.role),
        desired_version: Some(installed.version),
        active_version: Some(installed.version),
        error_code: None,
        error_message: None,
        updated_at: now_millis(),
    }
}

fn rejected_projection_status(
    id: &str,
    desired: Option<&InProcessProjectionInstalled>,
    error: &InstallError,
) -> InProcessProjectionStatus {
    let (phase, code) = projection_error_phase_code(error);
    InProcessProjectionStatus {
        id: id.to_string(),
        phase,
        implementation: projection_error_implementation(error)
            .or_else(|| desired.map(|value| value.implementation.clone())),
        role: projection_error_role(error).or_else(|| desired.map(|value| value.role)),
        desired_version: desired.map(|value| value.version),
        active_version: None,
        error_code: Some(code.into()),
        error_message: Some(error.to_string()),
        updated_at: now_millis(),
    }
}

fn projection_error_phase_code(error: &InstallError) -> (InProcessProjectionPhase, &'static str) {
    match error {
        InstallError::FeatureNotEnabled { .. } => (
            InProcessProjectionPhase::FeatureDisabled,
            "feature_not_enabled",
        ),
        InstallError::ImplementationUnavailable { .. } => (
            InProcessProjectionPhase::Unsupported,
            "implementation_unavailable",
        ),
        InstallError::RoleUnsupported { .. } => {
            (InProcessProjectionPhase::Unsupported, "role_unsupported")
        }
        InstallError::Decode { .. } => (InProcessProjectionPhase::Rejected, "decode_failed"),
        InstallError::Declaration { .. } => {
            (InProcessProjectionPhase::Rejected, "declaration_rejected")
        }
        InstallError::InvalidConfig { .. } => {
            (InProcessProjectionPhase::Rejected, "config_rejected")
        }
        InstallError::InvalidProvides { .. } => {
            (InProcessProjectionPhase::Rejected, "provides_rejected")
        }
        InstallError::Bootstrap(_) => (InProcessProjectionPhase::Rejected, "bootstrap_failed"),
        InstallError::MethodNotFound { .. } => {
            (InProcessProjectionPhase::Rejected, "method_not_found")
        }
        InstallError::Path { .. } => (InProcessProjectionPhase::Rejected, "path_invalid"),
        InstallError::State(_) => (InProcessProjectionPhase::Rejected, "state_failed"),
        InstallError::Assembly { .. } => (InProcessProjectionPhase::Rejected, "assembly_failed"),
    }
}

fn projection_error_implementation(error: &InstallError) -> Option<String> {
    match error {
        InstallError::ImplementationUnavailable { implementation }
        | InstallError::FeatureNotEnabled { implementation, .. }
        | InstallError::RoleUnsupported { implementation, .. }
        | InstallError::InvalidConfig { implementation, .. }
        | InstallError::InvalidProvides { implementation, .. } => Some(implementation.clone()),
        _ => None,
    }
}

fn projection_error_role(error: &InstallError) -> Option<xolotl_types::Role> {
    match error {
        InstallError::RoleUnsupported { role, .. } => Some(*role),
        _ => None,
    }
}

fn in_process_projection_status_prefix() -> Result<Path> {
    Ok(Path::parse(IN_PROCESS_PROJECTION_STATUS_PREFIX)?)
}

#[cfg(test)]
mod recovery_tests {
    use super::{
        in_process_projection_watch_pattern, retry_projection_operation, watch_projections,
    };
    use anyhow::ensure;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn terminal_projection_watch_failure_preserves_its_native_cause() -> anyhow::Result<()> {
        use std::sync::Arc;
        use std::task::{Context, Poll};
        use xolotl_sdk::Bootstrap;
        use xolotl_standard::StandardConfig;
        use xolotl_state::{StateEvent, StateStream, StateSubscription, StateWatchError};

        struct Stopped(Option<StateWatchError>);

        impl StateSubscription for Stopped {
            fn poll_next(
                &mut self,
                _context: &mut Context<'_>,
            ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
                Poll::Ready(match self.0.take() {
                    Some(error) => Err(error),
                    None => Ok(None),
                })
            }
        }

        let mut missing = Vec::new();
        for failure in [
            None,
            Some(StateWatchError::Backend("storage unavailable".into())),
        ] {
            let expected = failure.clone().unwrap_or(StateWatchError::Closed);
            let result = watch_projections(
                Arc::new(Bootstrap::in_memory()),
                StandardConfig::default(),
                in_process_projection_watch_pattern()?,
                StateStream::new(Stopped(failure)),
            )
            .await;
            if !result
                .is_err_and(|error| error.downcast_ref::<StateWatchError>() == Some(&expected))
            {
                missing.push(expected);
            }
        }
        ensure!(
            missing.is_empty(),
            "projection watcher discarded its terminal failures: {missing:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_reconciliation_retries_without_another_notification() -> anyhow::Result<()> {
        let attempts = AtomicUsize::new(0);
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            retry_projection_operation("test reconciliation", || {
                let number = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if number < 2 {
                        anyhow::bail!("temporary State failure")
                    }
                    Ok(number)
                }
            }),
        )
        .await?;
        ensure!(result == 2 && attempts.load(Ordering::SeqCst) == 3);
        Ok(())
    }
}
