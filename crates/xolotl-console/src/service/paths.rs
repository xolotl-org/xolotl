//! Request-facing adapters for canonical Console paths.

use super::{ConsoleError, validate_path_segment};
use crate::paths as contract;
use xolotl_types::Path;

pub(crate) fn external_installation_path(id: &str) -> Result<String, ConsoleError> {
    Ok(external_installation_target(id)?.to_string())
}

pub(crate) fn external_installation_target(id: &str) -> Result<Path, ConsoleError> {
    validate_path_segment(id, "external installation id")?;
    Ok(contract::external_installation_path(id)?)
}

pub(crate) fn external_manifest_path(platform: &str) -> Result<Path, ConsoleError> {
    validate_path_segment(platform, "external manifest platform")?;
    Ok(contract::external_manifest_path(platform)?)
}

pub(crate) fn projection_status_path(id: &str) -> Result<Path, ConsoleError> {
    validate_path_segment(id, "in-process projection id")?;
    Ok(contract::projection_status_path(id)?)
}

pub(crate) fn inference_backend_path(id: &str) -> Result<Path, ConsoleError> {
    validate_path_segment(id, "inference backend id")?;
    Ok(contract::inference_backend_path(id)?)
}

pub(crate) fn inference_model_path(id: &str) -> Result<Path, ConsoleError> {
    validate_path_segment(id, "inference model id")?;
    Ok(contract::inference_model_path(id)?)
}

pub(crate) fn inference_group_path(name: &str) -> Result<Path, ConsoleError> {
    validate_path_segment(name, "inference group name")?;
    Ok(contract::inference_group_path(name)?)
}

pub(crate) fn fact_path(process: u64) -> Result<Path, ConsoleError> {
    Ok(contract::fact_path(process)?)
}
