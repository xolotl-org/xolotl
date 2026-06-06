//! Side-effect classification: `Purity` (declared) and `ReplayClass` (derived).
//!
//! An author declares the coarser [`Purity`] of a method / effect ("is this
//! safe to replay?"). The kernel derives the finer [`ReplayClass`] from it,
//! and the persistence discipline (§9.3) follows automatically — only
//! [`ReplayClass::NonIdempotentEffect`] pays a write-ahead fsync barrier.

use serde::{Deserialize, Serialize};

/// How safe an effect is to replay. Declared by the method / `EffectCapability`
/// author (§4.2, §16.2). Sources that declare nothing (including MCP tools)
/// default to [`Purity::Effectful`] (§9.3).
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

/// The replay semantics the kernel actually enforces, derived from
/// [`Purity`] plus whether the operation observes external state (§9.3).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayClass {
    /// Same input → same output; can be recomputed on recovery.
    Deterministic,
    /// Reads external state; on recovery the recorded value is reused.
    Observation,
    /// External effect protected by an idempotency key; safe to retry.
    IdempotentEffect,
    /// Repeating produces a new effect; the *only* class that takes a
    /// write-ahead fsync barrier before the effect is issued (§9.3 / §15.1).
    NonIdempotentEffect,
}

impl Purity {
    /// Derive the [`ReplayClass`] (§9.3). A [`Purity::Pure`] method maps to
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

impl ReplayClass {
    /// Whether issuing this operation requires a write-ahead fsync barrier
    /// *before* the driver call (§9.3 / §15.1). True only for
    /// [`ReplayClass::NonIdempotentEffect`].
    pub fn needs_write_ahead_barrier(self) -> bool {
        matches!(self, ReplayClass::NonIdempotentEffect)
    }

    /// Whether the recorded outcome may be dropped from the recent tail
    /// (treated as cache loss) because it can be safely recomputed or reread.
    /// False once a value drives persistent control flow — that case is
    /// handled at the call site, not here.
    pub fn may_recompute(self) -> bool {
        matches!(self, ReplayClass::Deterministic | ReplayClass::Observation)
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
    fn only_non_idempotent_takes_barrier() {
        assert!(!ReplayClass::Deterministic.needs_write_ahead_barrier());
        assert!(!ReplayClass::Observation.needs_write_ahead_barrier());
        assert!(!ReplayClass::IdempotentEffect.needs_write_ahead_barrier());
        assert!(ReplayClass::NonIdempotentEffect.needs_write_ahead_barrier());
    }

    #[test]
    fn unspecified_purity_defaults_effectful() {
        assert_eq!(Purity::default(), Purity::Effectful);
    }
}
