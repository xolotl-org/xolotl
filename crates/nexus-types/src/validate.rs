//! Path semantic validation.
//!
//! `Path::parse` only checks syntax (character set, segment count > 0).
//! Semantic rules — minimum segment counts, reserved prefixes, scheme-
//! specific constraints — live in `PathValidator` implementations
//! registered in `PathRegistry`.
//!
//! Validators are invoked at Op boundaries (Register, Perform, StateRead,
//! StateWrite, Spawn), not at parse time. A path that parses successfully
//! may still be rejected by a validator when used in the wrong context.

use crate::{Failure, Path};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Validates a path's semantic correctness for a given scheme.
///
/// Implementations must be `Send + Sync` (they may be called from any
/// executor thread). They should be cheap — O(1) in path depth, no I/O.
pub trait PathValidator: Send + Sync + 'static {
    /// Validate `path`. Return `Ok(())` if the path is valid for this
    /// scheme, or a `Failure::PathInvalid` otherwise.
    fn validate(&self, path: &Path) -> Result<(), Failure>;
}

/// A collection of `PathValidator`s, keyed by scheme.
///
/// Schemes without a registered validator are implicitly permitted
/// (the system is open by default).
#[derive(Default)]
pub struct PathRegistry {
    validators: BTreeMap<String, Arc<dyn PathValidator>>,
}

impl PathRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            validators: BTreeMap::new(),
        }
    }

    /// Register a validator for a scheme.
    pub fn register(&mut self, scheme: &str, validator: Arc<dyn PathValidator>) {
        self.validators.insert(scheme.to_string(), validator);
    }

    /// Run the validator for `path`'s scheme if one is registered.
    /// Returns `Ok(())` if no validator is registered for the scheme.
    pub fn validate(&self, path: &Path) -> Result<(), Failure> {
        if let Some(v) = self.validators.get(path.scheme()) {
            v.validate(path)
        } else {
            Ok(())
        }
    }

    /// Whether no validators are registered.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}

// Built-in validators.

/// `state://` paths must have at least one segment.
pub struct StatePathValidator;

impl PathValidator for StatePathValidator {
    fn validate(&self, path: &Path) -> Result<(), Failure> {
        if path.segments().is_empty() {
            return Err(Failure::path_invalid(
                path.clone(),
                "state:// paths must have at least one segment",
            ));
        }
        Ok(())
    }
}

/// `effect://` paths must have at least two segments (domain/name).
pub struct EffectPathValidator;

impl PathValidator for EffectPathValidator {
    fn validate(&self, path: &Path) -> Result<(), Failure> {
        if path.segments().len() < 2 {
            return Err(Failure::path_invalid(
                path.clone(),
                "effect:// paths must have at least 2 segments (domain/name)",
            ));
        }
        Ok(())
    }
}

/// `process://` paths must have at least one segment (the identity).
pub struct ProcessPathValidator;

impl PathValidator for ProcessPathValidator {
    fn validate(&self, path: &Path) -> Result<(), Failure> {
        if path.segments().is_empty() {
            return Err(Failure::path_invalid(
                path.clone(),
                "process:// paths must have at least one segment",
            ));
        }
        Ok(())
    }
}

/// Create a `PathRegistry` pre-populated with the kernel's built-in
/// validators. Callers may add their own validators afterwards.
pub fn default_registry() -> PathRegistry {
    let mut r = PathRegistry::new();
    r.register("state", Arc::new(StatePathValidator));
    r.register("effect", Arc::new(EffectPathValidator));
    r.register("process", Arc::new(ProcessPathValidator));
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p;
    use anyhow::{bail, ensure};

    #[test]
    fn state_without_segment_is_rejected() -> anyhow::Result<()> {
        let v = StatePathValidator;
        let path = p("state://")?;
        let err = match v.validate(&path) {
            Ok(()) => bail!("state path without segment was accepted"),
            Err(error) => error,
        };
        ensure!(
            matches!(err, Failure::PathInvalid { .. }),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn state_with_segment_is_accepted() -> anyhow::Result<()> {
        let v = StatePathValidator;
        let path = p("state://memory")?;
        ensure!(v.validate(&path).is_ok(), "valid state path was rejected");
        Ok(())
    }

    #[test]
    fn effect_with_one_segment_is_rejected() -> anyhow::Result<()> {
        let v = EffectPathValidator;
        let path = p("effect://inference")?;
        let err = match v.validate(&path) {
            Ok(()) => bail!("effect path with one segment was accepted"),
            Err(error) => error,
        };
        ensure!(
            matches!(err, Failure::PathInvalid { .. }),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn effect_with_two_segments_is_accepted() -> anyhow::Result<()> {
        let v = EffectPathValidator;
        let path = p("effect://inference/infer")?;
        ensure!(v.validate(&path).is_ok(), "valid effect path was rejected");
        Ok(())
    }

    #[test]
    fn unregistered_scheme_passes() -> anyhow::Result<()> {
        let r = default_registry();
        let path = Path::parse("custom://tool/fetch")?;
        ensure!(r.validate(&path).is_ok(), "custom scheme was rejected");
        Ok(())
    }

    #[test]
    fn builtin_validators_cover_state_effect_process() -> anyhow::Result<()> {
        let r = default_registry();
        ensure!(
            r.validate(&p("state://memory/alice")?).is_ok(),
            "state path rejected"
        );
        ensure!(
            r.validate(&p("effect://x/post")?).is_ok(),
            "effect path rejected"
        );
        ensure!(
            r.validate(&p("process://alice")?).is_ok(),
            "process path rejected"
        );
        ensure!(
            r.validate(&p("state://")?).is_err(),
            "empty state path accepted"
        );
        ensure!(
            r.validate(&p("effect://infer")?).is_err(),
            "one-segment effect path accepted"
        );
        ensure!(
            r.validate(&p("process://")?).is_err(),
            "empty process path accepted"
        );
        Ok(())
    }
}
