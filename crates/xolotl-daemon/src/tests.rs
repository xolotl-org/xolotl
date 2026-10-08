use super::*;
use anyhow::Context as _;
use xolotl_standard::{
    InProcessProjectionInstallEntry, InProcessProjectionInstalled, InstallError,
};
use xolotl_types::{InProcessProjectionPhase, InProcessProjectionStatus, Path};

macro_rules! assert {
    ($condition:expr $(,)?) => {
        anyhow::ensure!($condition, "assertion failed: {}", stringify!($condition));
    };
    ($condition:expr, $($arg:tt)+) => {
        anyhow::ensure!($condition, $($arg)+);
    };
}

macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left, right) => anyhow::ensure!(
                left == right,
                "assertion failed: left != right\nleft: {left:?}\nright: {right:?}"
            ),
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        anyhow::ensure!($left == $right, $($arg)+);
    };
}

#[tokio::test]
async fn shutdown_background_tasks_observes_completed_cancelled_and_failed_tasks()
-> anyhow::Result<()> {
    let completed = tokio::spawn(async {});
    while !completed.is_finished() {
        tokio::task::yield_now().await;
    }
    let cancelled = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    let failed =
        tokio::spawn(async { std::panic::resume_unwind(Box::new("injected task failure")) });
    while !failed.is_finished() {
        tokio::task::yield_now().await;
    }
    let mut background = host_lifecycle::BackgroundTasks::default();
    background.push("completed", completed);
    background.push("cancelled", cancelled);
    background.push("failed", failed);
    let report = background.shutdown().await;
    assert_eq!(report.completed, 1);
    assert_eq!(report.cancelled, 1);
    assert_eq!(report.failed, 1);
    Ok(())
}

#[tokio::test]
async fn kernel_boots_with_standard_providers() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    install_standard(&boot, &StandardConfig::default())
        .map_err(|error| anyhow::anyhow!("installing standard providers: {error}"))?;
    assert!(boot.kernel().registry().resource_count() >= 5);
    Ok(())
}

#[tokio::test]
async fn projection_status_reconcile_deletes_stale_entries() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    projection::write_in_process_projection_status(
        &boot,
        &InProcessProjectionStatus {
            id: "stale".into(),
            phase: InProcessProjectionPhase::Active,
            implementation: Some("standard.fetch".into()),
            role: Some(xolotl_types::Role::Provider),
            desired_version: Some(1),
            active_version: Some(1),
            error_code: None,
            error_message: None,
            updated_at: 1,
        },
    )
    .await?;

    let installed = InProcessProjectionInstalled {
        id: "fetch".into(),
        implementation: "standard.fetch".into(),
        role: xolotl_types::Role::Provider,
        version: 1,
    };
    projection::reconcile_in_process_projection_report_status(
        &boot,
        vec![
            InProcessProjectionInstallEntry {
                id: "bad.id".into(),
                path: Path::parse("state://kernel/projections/in-process/bad.id")?,
                desired: None,
                result: Err(InstallError::Declaration {
                    id: "bad.id".into(),
                    message: "invalid projection id".into(),
                }),
            },
            InProcessProjectionInstallEntry {
                id: installed.id.clone(),
                path: Path::parse("state://kernel/projections/in-process/fetch")?,
                desired: Some(installed.clone()),
                result: Ok(installed),
            },
        ],
    )
    .await?;

    let stale_path =
        xolotl_types::in_process_projection::in_process_projection_status_path("stale")?;
    assert!(boot.kernel().state().read(&stale_path).await?.is_none());
    let active_path =
        xolotl_types::in_process_projection::in_process_projection_status_path("fetch")?;
    let active = boot
        .kernel()
        .state()
        .read(&active_path)
        .await?
        .context("active projection status missing")?;
    let status: InProcessProjectionStatus = serde_json::from_value(serde_json::to_value(active)?)?;
    assert_eq!(status.phase, InProcessProjectionPhase::Active);
    assert_eq!(status.id, "fetch");
    Ok(())
}
