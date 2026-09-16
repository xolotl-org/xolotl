//! Selected State declaration and fail-closed subscription ownership.

use super::wait_for_shutdown;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::watch;
use xolotl_gateway::{GatewayProfile, GatewayProfileDocument, GatewayRuntime};
use xolotl_gateway_grpc::ApplicationGrpcService;
use xolotl_state::host::Backend;
use xolotl_state::{StateEvent, StateStream};
use xolotl_types::{Path, Value};

pub(super) fn profile_path(name: &str) -> Result<Path> {
    Path::parse("state://kernel/gateway/profiles")?
        .try_push_literal(name)
        .context("application_gateway.profile must be one literal State path segment")
}

fn decode_profile(value: Value, name: &str) -> Result<GatewayProfileDocument> {
    let document: GatewayProfileDocument = serde_json::from_value(serde_json::to_value(value)?)
        .context("decode application Gateway profile document")?;
    anyhow::ensure!(
        document.profile_name() == name,
        "application Gateway profile_name does not match selected State path"
    );
    Ok(document)
}

pub(super) async fn load_profile(
    state: &Backend,
    path: &Path,
    name: &str,
) -> Result<GatewayProfile> {
    let value = state
        .read(path)
        .await?
        .with_context(|| format!("application Gateway profile is missing at {path}"))?;
    decode_profile(value, name)?
        .into_profile()
        .map_err(Into::into)
}

pub(super) async fn watch_profile(
    state: Backend,
    path: Path,
    name: String,
    mut events: StateStream,
    runtime: Arc<GatewayRuntime>,
    service: ApplicationGrpcService,
    shutdown: watch::Sender<bool>,
) {
    let mut stopping = shutdown.subscribe();
    loop {
        let event = tokio::select! {
            biased;
            () = wait_for_shutdown(&mut stopping) => break,
            event = events.recv() => event,
        };
        match event {
            Ok(event) if event.path() != &path => continue,
            Ok(StateEvent::Delete { .. }) => {
                tracing::warn!(%path, "application Gateway profile deleted; listener closing");
                break;
            }
            Ok(_) => {}
            Err(error) => {
                // Lost events can include a delete followed by recreation. A
                // snapshot alone cannot prove the active authority is still valid.
                tracing::error!(%path, %error, "application Gateway profile watch lost; listener closing");
                break;
            }
        }
        let value = tokio::select! {
            biased;
            () = wait_for_shutdown(&mut stopping) => break,
            value = state.read(&path) => value,
        };
        let value = match value {
            Ok(Some(value)) => value,
            Ok(None) => {
                tracing::warn!(%path, "application Gateway profile missing; listener closing");
                break;
            }
            Err(error) => {
                tracing::error!(%path, %error, "application Gateway profile read failed; listener closing");
                break;
            }
        };
        let document = match decode_profile(value, &name) {
            Ok(document) => document,
            Err(error) => {
                runtime.record_reload_failure(0, "invalid_profile_document");
                tracing::warn!(%path, %error, "application Gateway profile reload rejected");
                continue;
            }
        };
        let version = document.version();
        // Register-before-read may queue the snapshot's own mutation. Console
        // CAS gives changed declarations a new revision; do not reapply it.
        if version == runtime.profile_rev() {
            continue;
        }
        match document.into_profile() {
            Ok(profile) => match runtime.replace_profile(profile) {
                Ok(revision) => {
                    tracing::info!(%path, revision, "application Gateway profile reloaded");
                }
                Err(error) => {
                    tracing::warn!(%path, version, %error, "application Gateway profile reload rejected");
                }
            },
            Err(error) => {
                runtime.record_reload_failure(version, "invalid_profile_document");
                tracing::warn!(%path, version, %error, "application Gateway profile reload rejected");
            }
        }
    }
    service.shutdown();
    shutdown.send_replace(true);
}
