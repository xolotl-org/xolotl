//! Shared State namespace for Gateway-owned runtime records.
//!
//! Record-specific IDs and suffixes stay with their owning feature modules.

use xolotl_types::{Path, PathError};

/// Build an exact, local address below `state://gateway` from literal segments.
pub(crate) fn gateway_state_path(segments: &[&str]) -> Result<Path, PathError> {
    let mut path = Path::try_new("state")?.try_push_literal("gateway")?;
    for segment in segments {
        path = path.try_push_literal(segment)?;
    }
    Ok(path)
}
