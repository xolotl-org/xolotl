//! Host-owned admission for versioned kernel State configuration.

use std::{fmt, sync::Arc};
use thiserror::Error;
use xolotl_types::{Path, Value};

pub(crate) type ConfigValidator = dyn Fn(&Path, &Value) -> Result<(), String> + Send + Sync;

/// One host-owned configuration namespace. The validator receives the exact
/// requested path and the versioned value immediately before its State CAS.
/// It must reject malformed descendants of its namespace itself. Its error
/// string is returned to the caller and must never include secret values.
/// The callback must be pure and bounded: Console runs it on the host's
/// blocking-work port, and cancellation after admission cannot stop it.
#[derive(Clone)]
pub struct ConfigNamespaceAdmission {
    namespace: Path,
    validator: Arc<ConfigValidator>,
}

impl ConfigNamespaceAdmission {
    /// Claim a namespace and its descendants for one immutable host validator.
    /// Invalid, protected, and overlapping namespaces are rejected when the
    /// Console host is assembled.
    pub fn new(
        namespace: Path,
        validator: impl Fn(&Path, &Value) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            namespace,
            validator: Arc::new(validator),
        }
    }

    /// The path prefix exclusively owned by this validator.
    pub fn namespace(&self) -> &Path {
        &self.namespace
    }
}

impl fmt::Debug for ConfigNamespaceAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigNamespaceAdmission")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

/// Invalid ownership declarations fail host assembly before serving requests.
#[derive(Debug, Error)]
pub enum ConfigAdmissionConfigError {
    /// Admissions can only own concrete descendants of local `state://kernel`.
    #[error("config admission namespace must be a concrete local state://kernel descendant: {0}")]
    InvalidNamespace(Path),
    /// Only declared configuration spaces can be claimed. Runtime and Console
    /// private State subtrees are never configuration namespaces.
    #[error("path is not a claimable config admission namespace: {0}")]
    ReservedNamespace(Path),
    /// A path must never have two possible validation owners.
    #[error("config admission namespaces overlap: {first} and {second}")]
    OverlappingNamespaces {
        /// Namespace already claimed by an admission.
        first: Box<Path>,
        /// Conflicting namespace in the same host assembly.
        second: Box<Path>,
    },
}

/// Fixed at host assembly so write admission has no mutable routing state.
#[derive(Default)]
pub(crate) struct ConfigAdmissionRegistry {
    entries: Vec<ConfigNamespaceAdmission>,
}

impl ConfigAdmissionRegistry {
    pub(crate) fn new(
        mut entries: Vec<ConfigNamespaceAdmission>,
    ) -> Result<Self, ConfigAdmissionConfigError> {
        for entry in &entries {
            let path = entry.namespace();
            if path.scheme() != "state"
                || path.cluster().is_some()
                || !path.is_concrete()
                || path
                    .segments()
                    .first()
                    .is_none_or(|segment| segment != "kernel")
                || path.segments().len() < 2
            {
                return Err(ConfigAdmissionConfigError::InvalidNamespace(path.clone()));
            }
            if !is_claimable_namespace(path) {
                return Err(ConfigAdmissionConfigError::ReservedNamespace(path.clone()));
            }
        }
        entries.sort_by(|left, right| left.namespace.cmp(&right.namespace));
        for (index, left) in entries.iter().enumerate() {
            for right in entries.iter().skip(index + 1) {
                if left.namespace.is_prefix_of(&right.namespace)
                    || right.namespace.is_prefix_of(&left.namespace)
                {
                    return Err(ConfigAdmissionConfigError::OverlappingNamespaces {
                        first: Box::new(left.namespace.clone()),
                        second: Box::new(right.namespace.clone()),
                    });
                }
            }
        }
        Ok(Self { entries })
    }

    pub(crate) fn validator(&self, path: &Path) -> Result<Arc<ConfigValidator>, String> {
        self.entries
            .iter()
            .find(|entry| entry.namespace.is_prefix_of(path))
            .map(|entry| Arc::clone(&entry.validator))
            .ok_or_else(|| format!("no console write admission rule for {path}"))
    }

    /// Whether an installed owner can admit at least one path under a known
    /// action's collection. Paths are compared by components, not text prefix.
    pub(crate) fn overlaps_collection(&self, segments: &[&str]) -> bool {
        self.entries.iter().any(|entry| {
            entry
                .namespace
                .segments()
                .iter()
                .zip(segments)
                .all(|(actual, expected)| actual.as_str() == *expected)
        })
    }

    /// Whether an installed owner can admit the exact path of a singleton
    /// action, rather than merely one of its descendants.
    pub(crate) fn covers_path(&self, segments: &[&str]) -> bool {
        self.entries.iter().any(|entry| {
            let namespace = entry.namespace.segments();
            namespace.len() <= segments.len()
                && namespace
                    .iter()
                    .zip(segments)
                    .all(|(actual, expected)| actual.as_str() == *expected)
        })
    }
}

fn is_claimable_namespace(path: &Path) -> bool {
    let segments = path.segments();
    let namespace = segments.get(1).map(|segment| segment.as_str());
    let collection = segments.get(2).map(|segment| segment.as_str());
    let direct_entry = |collection_len: usize| {
        segments.len() == collection_len
            || (segments.len() == collection_len + 1
                && segments
                    .last()
                    .is_some_and(|id| xolotl_types::path::is_simple_id_segment(id)))
    };
    match (namespace, collection) {
        // Existing v1 declaration addresses remain available, while their
        // document shapes belong entirely to the installed host validators.
        (Some("gateway"), Some("profiles")) | (Some("projections"), Some("in-process")) => true,
        // These addresses can only be written by dedicated actions. Reject
        // owners that cannot cover any path those actions can construct.
        (Some("manifests"), _) => direct_entry(2),
        (Some("inference"), None) => true,
        (Some("inference"), Some("backends" | "models" | "groups")) => direct_entry(3),
        (Some("routing"), Some("inference")) => segments.len() == 3,
        // New owners use a dedicated subtree instead of claiming arbitrary
        // Kernel runtime records, including future private namespaces.
        (Some("config"), Some(owner)) => xolotl_types::path::is_simple_id_segment(owner),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    fn entry(path: &str) -> anyhow::Result<ConfigNamespaceAdmission> {
        Ok(ConfigNamespaceAdmission::new(
            Path::parse(path)?,
            |path, _value| {
                (path.segments().len() == 4)
                    .then_some(())
                    .ok_or_else(|| "expected a direct child".into())
            },
        ))
    }

    #[test]
    fn rejects_invalid_and_protected_ownership() -> anyhow::Result<()> {
        for path in [
            "state://kernel",
            "state://kernel/custom/**",
            "path://remote/state/kernel/custom",
        ] {
            ensure!(matches!(
                ConfigAdmissionRegistry::new(vec![entry(path)?]),
                Err(ConfigAdmissionConfigError::InvalidNamespace(_))
            ));
        }
        for path in [
            "state://kernel/console/custom",
            "state://kernel/audit",
            "state://kernel/external-installations",
            "state://kernel/idemp",
            "state://kernel/bootstrap",
            "state://kernel/approvals",
            "state://kernel/process",
            "state://kernel/source-events",
            "state://kernel/rate-limit",
            "state://kernel/config",
        ] {
            ensure!(matches!(
                ConfigAdmissionRegistry::new(vec![entry(path)?]),
                Err(ConfigAdmissionConfigError::ReservedNamespace(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_duplicate_and_nested_owners() -> anyhow::Result<()> {
        for other in [
            "state://kernel/config/custom",
            "state://kernel/config/custom/items",
        ] {
            ensure!(matches!(
                ConfigAdmissionRegistry::new(vec![
                    entry("state://kernel/config/custom")?,
                    entry(other)?
                ]),
                Err(ConfigAdmissionConfigError::OverlappingNamespaces { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn dedicated_owners_must_cover_an_addressable_action_path() -> anyhow::Result<()> {
        for path in [
            "state://kernel/manifests/bad.id",
            "state://kernel/manifests/acme/child",
            "state://kernel/inference/unknown",
            "state://kernel/inference/backends/bad.id",
            "state://kernel/inference/backends/acme/child",
            "state://kernel/routing/inference/child",
        ] {
            ensure!(
                matches!(
                    ConfigAdmissionRegistry::new(vec![entry(path)?]),
                    Err(ConfigAdmissionConfigError::ReservedNamespace(_))
                ),
                "unreachable owner {path} was accepted"
            );
        }
        for path in [
            "state://kernel/manifests",
            "state://kernel/manifests/acme",
            "state://kernel/inference",
            "state://kernel/inference/backends",
            "state://kernel/inference/backends/acme",
            "state://kernel/routing/inference",
        ] {
            ensure!(
                ConfigAdmissionRegistry::new(vec![entry(path)?]).is_ok(),
                "addressable owner {path} was rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn routes_only_to_the_claimed_namespace_and_rejects_unknown_children() -> anyhow::Result<()> {
        let registry = ConfigAdmissionRegistry::new(vec![entry("state://kernel/config/custom")?])?;
        let child = Path::parse("state://kernel/config/custom/a")?;
        let validate_child = registry.validator(&child).map_err(anyhow::Error::msg)?;
        ensure!(validate_child(&child, &Value::null()).is_ok());
        let nested = Path::parse("state://kernel/config/custom/a/extra")?;
        let validate_nested = registry.validator(&nested).map_err(anyhow::Error::msg)?;
        ensure!(validate_nested(&nested, &Value::null()).is_err());
        ensure!(
            registry
                .validator(&Path::parse("state://kernel/config/foobar/a")?)
                .is_err()
        );
        Ok(())
    }
}
