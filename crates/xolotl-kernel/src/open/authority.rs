//! Compile matched source grants into the handle's residual authority.

use crate::policy::{GrantAlternativesCheck, GrantCondition, PolicySnapshot};
use std::sync::Arc;
use xolotl_types::{ConstraintSet, Expiry, Grant};

/// An empty constraint set produces an unconditional snapshot. Constraints
/// within one grant are conjunctive; distinct grants are alternatives.
pub(super) fn compile_grant_snapshot(grants: &[&Grant]) -> PolicySnapshot {
    // A never-expiring, unconstrained grant makes every conditional alternative
    // redundant. Check the source first so this common case avoids copying the
    // other grants' constraints into residual candidates.
    if grants.iter().any(|grant| {
        grant.expires == Expiry::Never
            && grant.constraints.is_empty()
            && grant.selector.pattern.predicate.is_none()
    }) {
        return PolicySnapshot::empty();
    }
    let mut alternatives: Vec<_> = grants
        .iter()
        .map(|grant| {
            let mut constraints = effective_grant_constraints(grant);
            if constraints.predicates.len() > 1 {
                constraints.predicates.sort_unstable();
                constraints.predicates.dedup();
            }
            GrantCondition {
                constraints,
                expires: grant.expires,
            }
        })
        .collect();
    // Grant alternatives are pure OR conditions. Canonical order makes a
    // grant compilation independent of registry insertion order and drops repeated
    // checks without changing authority.
    if alternatives.len() > 1 {
        alternatives.sort_unstable();
        alternatives.dedup();
    }
    PolicySnapshot::new(vec![Arc::new(GrantAlternativesCheck { alternatives })])
}

fn effective_grant_constraints(grant: &Grant) -> ConstraintSet {
    let Some(predicate) = grant.selector.pattern.predicate.clone() else {
        return grant.constraints.clone();
    };
    let mut predicates = Vec::with_capacity(grant.constraints.predicates.len() + 1);
    predicates.push(predicate);
    predicates.extend(grant.constraints.predicates.iter().cloned());
    ConstraintSet { predicates }
}
