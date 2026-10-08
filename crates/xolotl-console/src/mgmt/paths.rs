//! Which kernel State addresses belong to dedicated management actions.
//!
//! Resource path syntax and named addresses live in `crate::paths`; this module
//! only decides whether a generic config action may manage a parsed address.

use xolotl_types::Path;

pub(super) fn is_local_kernel_state_subtree(path: &Path) -> bool {
    crate::paths::is_local_kernel_path(path) && path.segments().len() > 1
}

/// Includes the collection itself and every descendant. A generic State write
/// must never masquerade as a storage-catalog installation mutation.
pub(super) fn is_external_installation_subtree(path: &Path) -> bool {
    crate::paths::is_local_kernel_path(path)
        && path
            .segments()
            .get(1)
            .is_some_and(|segment| segment == "external-installations")
}

pub(crate) fn is_dedicated_management_path(path: &Path) -> bool {
    if !crate::paths::is_local_kernel_path(path) {
        return false;
    }
    let segments = path.segments();
    matches!(
        segments.get(1).map(|segment| segment.as_str()),
        Some(
            "console"
                | "external-installations"
                | "federation"
                | "external-pairings"
                | "external-sessions"
                | "external-credential-revocations"
                | "inference"
                | "manifests"
                | "projection-status"
                | "procs"
        )
    ) || (segments.get(1).is_some_and(|segment| segment == "routing")
        && segments
            .get(2)
            .is_some_and(|segment| segment == "inference"))
}

/// A generic config list cannot start above a dedicated subtree: doing so
/// would expose records that generic reads otherwise reject.
pub(super) fn contains_dedicated_management_subtree(path: &Path) -> bool {
    if is_dedicated_management_path(path) {
        return true;
    }
    if !crate::paths::is_local_kernel_path(path) {
        return false;
    }
    match path.segments() {
        [kernel] => kernel == "kernel",
        [kernel, routing] => kernel == "kernel" && routing == "routing",
        _ => false,
    }
}
