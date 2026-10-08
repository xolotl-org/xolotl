//! Authentication-specific validation before using the shared Console paths.

use super::{AuthError, validate_session_id, validate_username};
use crate::paths;
use xolotl_types::Path;

pub(crate) fn user_path(username: &str) -> Result<Path, AuthError> {
    validate_username(username)?;
    Ok(paths::user_path(username)?)
}

pub(crate) fn role_path(role: &str) -> Result<Path, AuthError> {
    validate_username(role)?;
    Ok(paths::role_path(role)?)
}

pub(super) fn session_path(sid: &str) -> Result<Path, AuthError> {
    validate_session_id(sid)?;
    Ok(paths::stored_session_path(sid)?)
}

pub(super) fn lockout_path(username: &str) -> Result<Path, AuthError> {
    validate_username(username)?;
    Ok(paths::lockout_path(username)?)
}
