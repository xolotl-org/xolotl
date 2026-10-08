//! Side-effect classification: `Purity` (declared) and `ReplayClass` (derived).
//!
//! An author declares the coarser [`Purity`] of a method / effect ("is this
//! safe to replay?"). The kernel derives the finer [`ReplayClass`] from it
//! to distinguish observations and effects. Classification does not require
//! persistent logging or authorize an automatic retry.

use serde::{Deserialize, Serialize};

/// How safe an effect is to replay. Declared by the method / `EffectCapability`
/// author. Sources that declare nothing (including MCP tools)
/// default to [`Purity::Effectful`].
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purity {
    /// No external side effects. Free to replay / recompute.
    Pure,
    /// Has an external effect but is safe to replay (idempotent, or the
    /// driver keys it with an idempotency key).
    Idempotent,
    /// Replay is unsafe — repeating the effect produces a new effect.
    #[default]
    Effectful,
}

/// The effect and retry semantics declared to the kernel, derived from
/// [`Purity`] plus whether the operation observes external state.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayClass {
    /// Same input yields the same output without observing external state.
    Deterministic,
    /// Reads external state; a later observation may differ.
    Observation,
    /// External effect protected by an idempotency key; safe to retry.
    IdempotentEffect,
    /// Repeating produces a new effect and is unsafe after an unknown outcome.
    NonIdempotentEffect,
}

impl Purity {
    /// Derive the [`ReplayClass`]. A [`Purity::Pure`] method maps to
    /// `Deterministic` for a pure computation, or `Observation` when it reads
    /// external state — the caller passes `observes_external` to disambiguate.
    pub fn replay_class(self, observes_external: bool) -> ReplayClass {
        match self {
            Purity::Pure if observes_external => ReplayClass::Observation,
            Purity::Pure => ReplayClass::Deterministic,
            Purity::Idempotent => ReplayClass::IdempotentEffect,
            Purity::Effectful => ReplayClass::NonIdempotentEffect,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purity_derives_replay_class() {
        assert_eq!(Purity::Pure.replay_class(false), ReplayClass::Deterministic);
        assert_eq!(Purity::Pure.replay_class(true), ReplayClass::Observation);
        assert_eq!(
            Purity::Idempotent.replay_class(false),
            ReplayClass::IdempotentEffect
        );
        assert_eq!(
            Purity::Effectful.replay_class(false),
            ReplayClass::NonIdempotentEffect
        );
    }

    #[test]
    fn unspecified_purity_defaults_effectful() {
        assert_eq!(Purity::default(), Purity::Effectful);
    }
}
