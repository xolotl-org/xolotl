//! Built-in path namespaces and their local reservation rules.

use super::Path;

/// Path prefixes reserved for the kernel. Non-kernel Processes cannot register
/// handlers or write state under these even with a non-kernel Grant; admission
/// and `open()` enforce it jointly.
pub const KERNEL_RESERVED_PREFIXES: &[&str] = &["state://kernel/", "effect://kernel/"];

/// Credential-reserved prefix: only the credential Driver opens these.
pub const VAULT_PREFIX: &str = "state://vault/";

/// Read-only history projection prefix.
pub const FACT_PREFIX: &str = "state://fact/";

/// Quarantine prefix: unsafe replays held for operator decision.
pub const QUARANTINE_PREFIX: &str = "state://quarantine/";

/// Streaming output prefix: `state://stream/<process>/<causal_pos>`.
pub const STREAM_PREFIX: &str = "state://stream/";

/// Bootstrap phase markers: `state://kernel/bootstrap/phase`.
pub const BOOTSTRAP_PHASE_PATH: &str = "state://kernel/bootstrap/phase";

/// Returns `true` if `path` is under a kernel-reserved prefix.
pub fn is_kernel_reserved(path: &Path) -> bool {
    path.cluster().is_none()
        && matches!(path.scheme(), "state" | "effect")
        && path.segments().first().map(|s| s.as_str()) == Some("kernel")
}

/// Returns `true` if `path` is under the credential-vault prefix.
pub fn is_vault_reserved(path: &Path) -> bool {
    path.cluster().is_none()
        && path.scheme() == "state"
        && path.segments().first().map(|s| s.as_str()) == Some("vault")
}

/// Returns `true` if `path` is under the read-only Fact projection prefix.
pub fn is_fact_reserved(path: &Path) -> bool {
    path.cluster().is_none()
        && path.scheme() == "state"
        && path.segments().first().map(|s| s.as_str()) == Some("fact")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn reserved_namespaces_are_local_and_segment_bound() -> anyhow::Result<()> {
        for (literal, kernel, vault, fact) in [
            ("state://kernel/jobs", true, false, false),
            ("effect://kernel/jobs", true, false, false),
            ("state://vault/secret", false, true, false),
            ("state://fact/1", false, false, true),
            ("state://kernelish/jobs", false, false, false),
            ("path://edge/state/kernel/jobs", false, false, false),
            ("path://edge/state/vault/secret", false, false, false),
            ("path://edge/state/fact/1", false, false, false),
        ] {
            let path = Path::parse(literal)?;
            ensure!(is_kernel_reserved(&path) == kernel, "{literal}");
            ensure!(is_vault_reserved(&path) == vault, "{literal}");
            ensure!(is_fact_reserved(&path) == fact, "{literal}");
        }
        Ok(())
    }
}
