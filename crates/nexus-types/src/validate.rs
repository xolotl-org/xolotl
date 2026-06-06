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
    pub fn new() -> Self {
        Self {
            validators: BTreeMap::new(),
        }
    }

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

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}

// ── built-in validators ───────────────────────────────────────────

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

    #[test]
    fn state_without_segment_is_rejected() {
        let v = StatePathValidator;
        let path = p("state://");
        let err = v.validate(&path).unwrap_err();
        assert!(matches!(err, Failure::PathInvalid { .. }));
    }

    #[test]
    fn state_with_segment_is_accepted() {
        let v = StatePathValidator;
        let path = p("state://memory");
        assert!(v.validate(&path).is_ok());
    }

    #[test]
    fn effect_with_one_segment_is_rejected() {
        let v = EffectPathValidator;
        let path = p("effect://inference");
        let err = v.validate(&path).unwrap_err();
        assert!(matches!(err, Failure::PathInvalid { .. }));
    }

    #[test]
    fn effect_with_two_segments_is_accepted() {
        let v = EffectPathValidator;
        let path = p("effect://inference/infer");
        assert!(v.validate(&path).is_ok());
    }

    #[test]
    fn unregistered_scheme_passes() {
        let r = default_registry();
        let path = Path::parse("mcp-res://tool/fetch").unwrap();
        assert!(r.validate(&path).is_ok());
    }

    #[test]
    fn builtin_validators_cover_state_effect_process() {
        let r = default_registry();
        assert!(r.validate(&p("state://memory/alice")).is_ok());
        assert!(r.validate(&p("effect://x/post")).is_ok());
        assert!(r.validate(&p("process://alice")).is_ok());
        assert!(r.validate(&p("state://")).is_err());
        assert!(r.validate(&p("effect://infer")).is_err());
        assert!(r.validate(&p("process://")).is_err());
    }
}
