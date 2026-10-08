//! The host-owned directory for concrete identity paths.
//!
//! A compact `IdentityRef` is meaningful only in the directory that issued it.
//! Implementations must commit both directions and the high water atomically,
//! and must never reuse an issued number, even after records are retired.

use std::{collections::HashMap, sync::Arc};
use xolotl_types::{IdentityRef, Path};

/// Failure to register or verify an identity in its owning namespace.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdentityError {
    /// Only nonempty, concrete, local `identity://` paths can name an identity.
    #[error("identity path must be a nonempty concrete local identity:// path")]
    InvalidPath,
    /// An identity supplied by a caller is not registered.
    #[error("identity {0} is not registered")]
    Missing(IdentityRef),
    /// A path and number do not belong to the same registered identity.
    #[error("identity path and number do not match")]
    Mismatch,
    /// The persisted two-way index or its allocation high water is inconsistent.
    #[error("identity directory is inconsistent: {0}")]
    Corrupt(&'static str),
    /// No unused non-root number remains.
    #[error("identity number space is exhausted")]
    Exhausted,
    /// The directory could not establish the result of a storage operation.
    #[error("identity directory storage: {0}")]
    Storage(String),
}

/// Atomic identity namespace owned by one host storage domain.
///
/// A successful registration is durable before returning if this directory is
/// persistent. Read methods must reject inconsistent forward/reverse entries;
/// they must never repair them by creating a replacement identity.
pub trait IdentityDirectory: Send + Sync + 'static {
    /// Return an existing identity or atomically register a new one.
    fn resolve_or_register(&self, path: &Path) -> Result<IdentityRef, IdentityError>;
    /// Read only; a missing path remains missing.
    fn lookup(&self, path: &Path) -> Result<Option<IdentityRef>, IdentityError>;
    /// Read only; root has no corresponding path.
    fn path_for(&self, identity: IdentityRef) -> Result<Option<Path>, IdentityError>;
    /// Read only; verify a compact reference in both directions. Backends may
    /// override this to check both indexes in one storage snapshot.
    fn verify(&self, identity: IdentityRef) -> Result<(), IdentityError> {
        if identity == IdentityRef::ROOT {
            return Ok(());
        }
        let path = self
            .path_for(identity)?
            .ok_or(IdentityError::Missing(identity))?;
        validate_path(&path)?;
        if self.lookup(&path)? != Some(identity) {
            return Err(IdentityError::Mismatch);
        }
        Ok(())
    }
    /// Check the complete directory, including high water and both directions.
    fn validate(&self) -> Result<(), IdentityError>;
}

/// Cloneable, checked access to a host's identity namespace.
#[derive(Clone)]
pub struct IdentityRegistry(Arc<dyn IdentityDirectory>);

impl IdentityRegistry {
    /// Wrap a host implementation of the identity directory.
    pub fn new(directory: Arc<dyn IdentityDirectory>) -> Self {
        Self(directory)
    }

    /// Create an isolated, volatile identity namespace.
    pub fn in_memory() -> Self {
        Self::new(Arc::new(InMemoryIdentityDirectory::new()))
    }

    /// Register a concrete identity, or reuse its existing number.
    pub fn resolve_or_register(&self, path: &Path) -> Result<IdentityRef, IdentityError> {
        validate_path(path)?;
        let identity = self.0.resolve_or_register(path)?;
        if identity == IdentityRef::ROOT
            || self.0.path_for(identity)?.as_ref() != Some(path)
            || self.0.lookup(path)? != Some(identity)
        {
            return Err(IdentityError::Mismatch);
        }
        Ok(identity)
    }

    /// Look up an already registered path without changing the namespace.
    pub fn lookup(&self, path: &Path) -> Result<Option<IdentityRef>, IdentityError> {
        validate_path(path)?;
        let identity = self.0.lookup(path)?;
        if let Some(identity) = identity
            && (identity == IdentityRef::ROOT || self.0.path_for(identity)?.as_ref() != Some(path))
        {
            return Err(IdentityError::Mismatch);
        }
        Ok(identity)
    }

    /// Return the registered path for a non-root identity.
    pub fn path_for(&self, identity: IdentityRef) -> Result<Option<Path>, IdentityError> {
        let path = self.0.path_for(identity)?;
        if let Some(path) = &path {
            validate_path(path)?;
            if identity == IdentityRef::ROOT || self.0.lookup(path)? != Some(identity) {
                return Err(IdentityError::Mismatch);
            }
        }
        Ok(path)
    }

    /// Reject a retained identity that is not present in both indexes.
    pub fn verify(&self, identity: IdentityRef) -> Result<(), IdentityError> {
        if identity == IdentityRef::ROOT {
            return Ok(());
        }
        self.0.verify(identity)
    }

    /// Check a retained `(identity, path)` pair without registering either one.
    pub fn verify_binding(&self, identity: IdentityRef, path: &Path) -> Result<(), IdentityError> {
        validate_path(path)?;
        if identity == IdentityRef::ROOT {
            return Err(IdentityError::Mismatch);
        }
        match (self.0.lookup(path)?, self.0.path_for(identity)?) {
            (Some(found), Some(reverse)) if found == identity && &reverse == path => Ok(()),
            (Some(_), _) => Err(IdentityError::Mismatch),
            (None, None) => Err(IdentityError::Missing(identity)),
            _ => Err(IdentityError::Mismatch),
        }
    }

    /// Validate the whole namespace before admitting retained work.
    pub fn validate(&self) -> Result<(), IdentityError> {
        self.0.validate()
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::in_memory()
    }
}

/// Require a local identity namespace, at least one literal segment, and no wildcard.
pub fn validate_path(path: &Path) -> Result<(), IdentityError> {
    if path.cluster().is_some()
        || path.scheme() != "identity"
        || path.segments().is_empty()
        || !path.is_concrete()
    {
        return Err(IdentityError::InvalidPath);
    }
    Ok(())
}

#[derive(Default)]
struct DirectoryState {
    high_water: u64,
    by_path: HashMap<Path, IdentityRef>,
    by_ref: HashMap<IdentityRef, Path>,
}

/// In-memory implementation with the same two-way and monotonic rules as storage.
#[derive(Default)]
pub struct InMemoryIdentityDirectory {
    state: parking_lot::Mutex<DirectoryState>,
}

impl InMemoryIdentityDirectory {
    /// Create an empty namespace; number zero is reserved for ROOT.
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdentityDirectory for InMemoryIdentityDirectory {
    fn resolve_or_register(&self, path: &Path) -> Result<IdentityRef, IdentityError> {
        validate_path(path)?;
        let mut state = self.state.lock();
        if let Some(identity) = state.by_path.get(path).copied() {
            if state.by_ref.get(&identity) != Some(path) || identity.get() > state.high_water {
                return Err(IdentityError::Corrupt(
                    "forward entry has no matching reverse entry",
                ));
            }
            return Ok(identity);
        }
        let next = state
            .high_water
            .checked_add(1)
            .ok_or(IdentityError::Exhausted)?;
        let identity = IdentityRef::new(next);
        if state.by_ref.contains_key(&identity) {
            return Err(IdentityError::Corrupt(
                "allocated number is already present",
            ));
        }
        state.by_path.insert(path.clone(), identity);
        state.by_ref.insert(identity, path.clone());
        state.high_water = next;
        Ok(identity)
    }

    fn lookup(&self, path: &Path) -> Result<Option<IdentityRef>, IdentityError> {
        validate_path(path)?;
        let state = self.state.lock();
        let Some(identity) = state.by_path.get(path).copied() else {
            return Ok(None);
        };
        if identity == IdentityRef::ROOT
            || identity.get() > state.high_water
            || state.by_ref.get(&identity) != Some(path)
        {
            return Err(IdentityError::Corrupt(
                "forward entry has no matching reverse entry",
            ));
        }
        Ok(Some(identity))
    }

    fn path_for(&self, identity: IdentityRef) -> Result<Option<Path>, IdentityError> {
        if identity == IdentityRef::ROOT {
            return Ok(None);
        }
        let state = self.state.lock();
        let Some(path) = state.by_ref.get(&identity) else {
            return Ok(None);
        };
        if identity.get() > state.high_water || state.by_path.get(path) != Some(&identity) {
            return Err(IdentityError::Corrupt(
                "reverse entry has no matching forward entry",
            ));
        }
        Ok(Some(path.clone()))
    }

    fn verify(&self, identity: IdentityRef) -> Result<(), IdentityError> {
        if identity == IdentityRef::ROOT {
            return Ok(());
        }
        let state = self.state.lock();
        let path = state
            .by_ref
            .get(&identity)
            .ok_or(IdentityError::Missing(identity))?;
        if identity.get() > state.high_water || state.by_path.get(path) != Some(&identity) {
            return Err(IdentityError::Corrupt(
                "reverse entry has no matching forward entry",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), IdentityError> {
        let state = self.state.lock();
        if state.by_path.len() != state.by_ref.len() {
            return Err(IdentityError::Corrupt("index lengths differ"));
        }
        for (path, identity) in &state.by_path {
            validate_path(path)?;
            if *identity == IdentityRef::ROOT
                || identity.get() > state.high_water
                || state.by_ref.get(identity) != Some(path)
            {
                return Err(IdentityError::Corrupt("index entries differ"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    struct OneSidedDirectory {
        path: Path,
        identity: IdentityRef,
        forward: bool,
        reverse: bool,
    }

    impl IdentityDirectory for OneSidedDirectory {
        fn resolve_or_register(&self, _path: &Path) -> Result<IdentityRef, IdentityError> {
            Ok(self.identity)
        }

        fn lookup(&self, _path: &Path) -> Result<Option<IdentityRef>, IdentityError> {
            Ok(self.forward.then_some(self.identity))
        }

        fn path_for(&self, _identity: IdentityRef) -> Result<Option<Path>, IdentityError> {
            Ok(self.reverse.then(|| self.path.clone()))
        }

        fn validate(&self) -> Result<(), IdentityError> {
            Ok(())
        }
    }

    #[test]
    fn directory_reuses_path_but_never_conflates_distinct_paths() -> anyhow::Result<()> {
        let directory = IdentityRegistry::in_memory();
        let a = Path::parse("identity://accounts/a")?;
        let b = Path::parse("identity://accounts/b")?;
        let first = directory.resolve_or_register(&a)?;
        ensure!(directory.resolve_or_register(&a)? == first);
        let second = directory.resolve_or_register(&b)?;
        ensure!(first != second);
        directory.verify_binding(first, &a)?;
        ensure!(matches!(
            directory.verify_binding(first, &b),
            Err(IdentityError::Mismatch)
        ));
        ensure!(matches!(
            directory.verify(IdentityRef::new(3)),
            Err(IdentityError::Missing(_))
        ));
        directory.validate()?;
        Ok(())
    }

    #[test]
    fn only_concrete_identity_paths_can_be_registered() -> anyhow::Result<()> {
        let directory = IdentityRegistry::in_memory();
        for path in [
            "identity://",
            "identity://accounts/*",
            "path://remote/identity/accounts/a",
            "process://accounts/a",
        ] {
            ensure!(matches!(
                directory.resolve_or_register(&Path::parse(path)?),
                Err(IdentityError::InvalidPath)
            ));
        }
        Ok(())
    }

    #[test]
    fn registry_rejects_one_sided_host_directory_answers() -> anyhow::Result<()> {
        let path = Path::parse("identity://accounts/a")?;
        let identity = IdentityRef::new(1);
        for (forward, reverse) in [(true, false), (false, true)] {
            let directory = IdentityRegistry::new(Arc::new(OneSidedDirectory {
                path: path.clone(),
                identity,
                forward,
                reverse,
            }));
            ensure!(matches!(
                directory.resolve_or_register(&path),
                Err(IdentityError::Mismatch)
            ));
            ensure!(matches!(
                directory.verify_binding(identity, &path),
                Err(IdentityError::Mismatch)
            ));
            if forward {
                ensure!(matches!(
                    directory.lookup(&path),
                    Err(IdentityError::Mismatch)
                ));
            } else {
                ensure!(matches!(
                    directory.verify(identity),
                    Err(IdentityError::Mismatch)
                ));
            }
        }
        Ok(())
    }
}
