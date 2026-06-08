//! Audit projection (§21.3 / §9.1): audit is **not** a separate log — it is a
//! derived projection over the Fact stream that attaches tags, indexes, and
//! alerts. Rules live in `state://kernel/audit/rules` and hot-update; this
//! module is the pure, wasm-safe derivation a projector applies to each Fact.
//!
//! The kernel never writes a second audit record; a projector reads Facts and
//! emits [`AuditTag`]s, which downstream tooling indexes or alerts on.

use crate::operation::{DecisionTag, Fact};
use serde::{Deserialize, Serialize};

/// A tag a projector attaches to a Fact (§21.3). These are the standard audit
/// classifications; `Custom` carries rule-defined labels.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "tag")]
pub enum AuditTag {
    /// The operation touched protected/sensitive data (taint carries Protected).
    SensitiveData,
    /// The acting identity differs from the caller's process identity — a
    /// cross-identity (delegated) action worth surfacing.
    CrossIdentity,
    /// The operation's modeled cost exceeded the rule threshold.
    HighCost {
        /// Settled or projected cost in micro-USD.
        micro_usd: u64,
    },
    /// A compliance-relevant operation (rule-matched).
    Compliance {
        /// Rule label that matched.
        rule: String,
    },
    /// An alert-worthy event (rule-matched); projectors may page on these.
    Alert {
        /// Rule label that matched.
        rule: String,
    },
    /// A producer-defined audit label carried in redacted Fact metadata.
    Custom {
        /// Custom audit label.
        label: String,
    },
}

/// Hot-updatable audit rules (`state://kernel/audit/rules`, §21.3). Empty rules
/// still produce the structural tags (sensitive_data / cross_identity) that are
/// derivable from the Fact alone.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditRules {
    /// Operations whose modeled cost (micro-USD) meets/exceeds this are tagged
    /// `HighCost`. `None` disables the cost rule.
    pub high_cost_micro_usd: Option<u64>,
    /// Resource-id prefixes (as integers) flagged `Compliance` with the label.
    #[serde(default)]
    pub compliance_resources: Vec<(u64, String)>,
    /// Decision tags that always raise an `Alert` (e.g. quarantine).
    #[serde(default)]
    pub alert_on_decisions: Vec<String>,
}

impl AuditRules {
    /// Derive the audit tags for one Fact (§9.1 projection). `cost_micro_usd` is
    /// the settled cost the billing projection computed for this op (0 if free
    /// / unknown). The result is purely a function of the Fact + rules, so it is
    /// reproducible and needs no separate log.
    pub fn tags_for(&self, fact: &Fact, cost_micro_usd: u64) -> Vec<AuditTag> {
        let mut tags = Vec::new();

        // Structural tags derivable from the Fact alone (rule-independent).
        if let Some(label) = custom_label(fact) {
            tags.push(AuditTag::Custom { label });
        }
        if fact.taint.has_protected() {
            tags.push(AuditTag::SensitiveData);
        }
        // Cross-identity: the running process acts as an identity other than the
        // kernel's default for it. We approximate with caller≠acting hashing:
        // the caller process id and acting identity diverging is the signal a
        // delegation occurred (§21.3). Callers map process→identity upstream;
        // here we surface any non-root acting under a different-id caller.
        if fact.acting != crate::IdentityRef::ROOT && fact.acting.get() != fact.caller.get() {
            tags.push(AuditTag::CrossIdentity);
        }

        // Rule-driven tags.
        if let Some(threshold) = self.high_cost_micro_usd
            && cost_micro_usd >= threshold
        {
            tags.push(AuditTag::HighCost {
                micro_usd: cost_micro_usd,
            });
        }
        for (rid, label) in &self.compliance_resources {
            if fact.resource.get() == *rid {
                tags.push(AuditTag::Compliance {
                    rule: label.clone(),
                });
            }
        }
        let decision_name = decision_name(fact.decision);
        for rule in &self.alert_on_decisions {
            if rule == decision_name {
                tags.push(AuditTag::Alert { rule: rule.clone() });
            }
        }
        tags
    }
}

fn decision_name(d: DecisionTag) -> &'static str {
    match d {
        DecisionTag::Ok => "ok",
        DecisionTag::Denied => "denied",
        DecisionTag::RejectedByPolicy => "rejected_by_policy",
        DecisionTag::DriverError => "driver_error",
        DecisionTag::Timeout => "timeout",
        DecisionTag::Cancelled => "cancelled",
        DecisionTag::Quarantined => "quarantined",
    }
}

fn custom_label(fact: &Fact) -> Option<String> {
    let crate::OutcomeRef::Inline(crate::Value::Map(fields)) = &fact.outcome_ref else {
        return None;
    };
    fields
        .get("event")
        .and_then(crate::Value::as_str)
        .filter(|label| label.starts_with("console_"))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{HandleId, MethodId, NodeId, ProcessId, ResourceId, Timestamp};
    use crate::operation::{OperationId, OutcomeRef, ValueRef};
    use crate::replay::ReplayClass;
    use crate::taint::{TaintSet, TaintSource};
    use crate::{IdentityRef, Path, Value};

    fn fact(
        taint: TaintSet,
        acting: IdentityRef,
        caller: ProcessId,
        resource: u64,
        decision: DecisionTag,
    ) -> Fact {
        Fact {
            id: OperationId::new(caller, NodeId::new(1), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller,
            acting,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(resource),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Null),
            taint,
            decision,
            outcome_ref: OutcomeRef::None,
            batch: None,
            replay: ReplayClass::Deterministic,
            timestamp: Timestamp::millis(0),
        }
    }

    #[test]
    fn protected_taint_yields_sensitive_data_tag() {
        let t = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://vault/x").unwrap(),
        });
        let f = fact(t, IdentityRef::ROOT, ProcessId::new(1), 1, DecisionTag::Ok);
        let tags = AuditRules::default().tags_for(&f, 0);
        assert!(tags.contains(&AuditTag::SensitiveData));
    }

    #[test]
    fn cross_identity_tag_on_delegated_action() {
        // acting (5) differs from caller process (1) and isn't ROOT.
        let f = fact(
            TaintSet::pristine(),
            IdentityRef::new(5),
            ProcessId::new(1),
            1,
            DecisionTag::Ok,
        );
        let tags = AuditRules::default().tags_for(&f, 0);
        assert!(tags.contains(&AuditTag::CrossIdentity));
    }

    #[test]
    fn high_cost_rule_fires_at_threshold() {
        let f = fact(
            TaintSet::pristine(),
            IdentityRef::ROOT,
            ProcessId::new(1),
            1,
            DecisionTag::Ok,
        );
        let rules = AuditRules {
            high_cost_micro_usd: Some(1000),
            ..Default::default()
        };
        assert!(
            rules
                .tags_for(&f, 1500)
                .contains(&AuditTag::HighCost { micro_usd: 1500 })
        );
        // Below threshold → no tag.
        assert!(rules.tags_for(&f, 500).is_empty());
    }

    #[test]
    fn alert_rule_matches_decision() {
        let f = fact(
            TaintSet::pristine(),
            IdentityRef::ROOT,
            ProcessId::new(1),
            1,
            DecisionTag::Quarantined,
        );
        let rules = AuditRules {
            alert_on_decisions: vec!["quarantined".into()],
            ..Default::default()
        };
        assert!(rules.tags_for(&f, 0).contains(&AuditTag::Alert {
            rule: "quarantined".into()
        }));
    }

    #[test]
    fn redacted_console_event_yields_custom_tag() {
        let mut f = fact(
            TaintSet::author(),
            IdentityRef::ROOT,
            ProcessId::new(1),
            1,
            DecisionTag::Ok,
        );
        f.outcome_ref = OutcomeRef::Inline(Value::Map(std::collections::BTreeMap::from([(
            "event".into(),
            Value::Str("console_login".into()),
        )])));
        assert!(
            AuditRules::default()
                .tags_for(&f, 0)
                .contains(&AuditTag::Custom {
                    label: "console_login".into()
                })
        );
    }
}
