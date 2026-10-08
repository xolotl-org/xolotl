//! Audit projection: audit is derived from the Fact stream and attaches tags,
//! indexes, and alerts. Rules live in `state://kernel/audit/rules` and
//! hot-update; this module is the pure, wasm-safe derivation a projector
//! applies to each Fact.
//!
//! The kernel never writes a second audit record; a projector reads Facts and
//! emits [`AuditTag`]s, which downstream tooling indexes or alerts on.

use crate::operation::{DecisionTag, Fact};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

/// Administrative source position for gateway audit Facts. The position alone
/// is not an event discriminator: ordinary graphs may use the same position.
/// Recognition requires the complete [`gateway_audit_event`] envelope,
/// including the administrative invocation ticket zero.
pub const GATEWAY_AUDIT_NODE: crate::NodeId = crate::NodeId::new(u32::MAX - 1);

/// Read an application event label from a well-formed gateway audit Fact.
///
/// Ordinary Operations use nonzero invocation tickets and active handles;
/// returning an `event` field cannot turn their results into gateway metadata.
/// Lifecycle Facts use their own administrative position. Event names and
/// `details` belong to the application and carry no authentication guarantee.
/// This validates structure from a trusted Fact writer, not writer authenticity.
pub fn gateway_audit_event(fact: &Fact) -> Option<&str> {
    if fact.schema_version != Fact::SCHEMA_VERSION
        || fact.id.position != GATEWAY_AUDIT_NODE
        || fact.id.invocation.get() != 0
        || fact.id.attempt != 0
        || fact.id.process != fact.caller
        || fact.caller_identity != Some(crate::IdentityRef::ROOT)
        || fact.acting != crate::IdentityRef::ROOT
        || fact.handle != crate::HandleId::new(0, 0)
        || fact.resource.get() != 0
        || fact.method.get() != 0
        || !fact.input.is_null()
        || !matches!(fact.taint.sources(), [crate::TaintSource::AuthorConstant])
        || fact.decision != DecisionTag::Ok
        || fact.replay != crate::ReplayClass::Observation
        || fact.batch.is_some()
    {
        return None;
    }
    let fields = fact.outcome.as_ref()?.as_map()?;
    if fields.keys().any(|key| {
        !matches!(
            key,
            "event" | "outcome" | "username" | "source_addr" | "details"
        )
    }) || ["username", "source_addr"].iter().any(|key| {
        fields
            .get(key)
            .is_some_and(|value| value.as_str().is_none())
    }) {
        return None;
    }
    fields
        .get("outcome")?
        .as_str()
        .filter(|outcome| !outcome.is_empty())?;
    fields
        .get("event")?
        .as_str()
        .filter(|event| !event.is_empty())
}

/// A tag a projector attaches to a Fact. These are the standard audit
/// classifications; `Custom` carries rule-defined labels.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "tag")]
pub enum AuditTag {
    /// The operation touched protected/sensitive data (taint carries Protected).
    SensitiveData,
    /// The attempt's acting identity differs from the observed caller identity.
    /// This describes an identity switch, including denied attempts; it does
    /// not establish authorized delegation. An unknown caller identity yields
    /// no cross-identity classification.
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

/// Hot-updatable audit rules. Empty rules
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
    /// Derive the audit tags for one Fact. `cost_micro_usd` is
    /// the settled cost the billing projection computed for this op (0 if free
    /// / unknown). The result is purely a function of the Fact + rules, so it is
    /// reproducible and needs no separate log.
    pub fn tags_for(&self, fact: &Fact, cost_micro_usd: u64) -> Vec<AuditTag> {
        let mut tags = Vec::new();

        // Structural tags derivable from the Fact alone (rule-independent).
        if let Some(label) = gateway_audit_event(fact) {
            tags.push(AuditTag::Custom {
                label: label.to_string(),
            });
        }
        if fact.taint.has_protected() {
            tags.push(AuditTag::SensitiveData);
        }
        if fact
            .caller_identity
            .is_some_and(|identity| identity != fact.acting)
        {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{
        ExecutionId, HandleId, InvocationId, MethodId, NodeId, ProcessId, ResourceId, Timestamp,
    };
    use crate::operation::OperationId;
    use crate::replay::ReplayClass;
    use crate::taint::{TaintSet, TaintSource};
    use crate::{IdentityRef, Path, Value};
    use anyhow::ensure;

    fn fact(
        taint: TaintSet,
        acting: IdentityRef,
        caller: ProcessId,
        resource: u64,
        decision: DecisionTag,
    ) -> Fact {
        Fact {
            id: OperationId::new(
                caller,
                ExecutionId::FIRST,
                InvocationId::new(1),
                NodeId::new(1),
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller,
            caller_identity: Some(IdentityRef::ROOT),
            acting,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(resource),
            method: MethodId::new(0),
            input: Value::null(),
            taint,
            decision,
            outcome: None,
            batch: None,
            replay: ReplayClass::Deterministic,
            timestamp: Timestamp::millis(0),
        }
    }

    #[test]
    fn protected_taint_yields_sensitive_data_tag() -> anyhow::Result<()> {
        let t = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://vault/x")?,
        });
        let f = fact(t, IdentityRef::ROOT, ProcessId::new(1), 1, DecisionTag::Ok);
        let tags = AuditRules::default().tags_for(&f, 0);
        ensure!(
            tags.contains(&AuditTag::SensitiveData),
            "sensitive data tag missing"
        );
        Ok(())
    }

    #[test]
    fn same_identity_does_not_depend_on_process_coordinates() {
        let mut f = fact(
            TaintSet::pristine(),
            IdentityRef::new(5),
            ProcessId::new(1),
            1,
            DecisionTag::Ok,
        );
        f.caller_identity = Some(IdentityRef::new(5));
        assert!(AuditRules::default().tags_for(&f, 0).is_empty());
    }

    #[test]
    fn cross_identity_is_not_hidden_by_matching_process_and_acting_numbers() {
        let mut f = fact(
            TaintSet::pristine(),
            IdentityRef::new(5),
            ProcessId::new(5),
            1,
            DecisionTag::Ok,
        );
        f.caller_identity = Some(IdentityRef::new(9));
        assert_eq!(
            AuditRules::default().tags_for(&f, 0),
            vec![AuditTag::CrossIdentity]
        );
    }

    #[test]
    fn cross_identity_includes_switches_to_and_from_root() {
        for (caller_identity, acting) in [
            (IdentityRef::new(5), IdentityRef::ROOT),
            (IdentityRef::ROOT, IdentityRef::new(5)),
        ] {
            let mut f = fact(
                TaintSet::pristine(),
                acting,
                ProcessId::new(1),
                1,
                DecisionTag::Ok,
            );
            f.caller_identity = Some(caller_identity);
            assert_eq!(
                AuditRules::default().tags_for(&f, 0),
                vec![AuditTag::CrossIdentity]
            );
        }
    }

    #[test]
    fn unknown_caller_identity_is_not_inferred_from_other_coordinates() {
        for acting in [IdentityRef::ROOT, IdentityRef::new(1), IdentityRef::new(5)] {
            let mut f = fact(
                TaintSet::pristine(),
                acting,
                ProcessId::new(1),
                1,
                DecisionTag::Ok,
            );
            f.caller_identity = None;
            assert!(AuditRules::default().tags_for(&f, 0).is_empty());
        }
    }

    #[test]
    fn cross_identity_records_denied_attempts_without_asserting_delegation() {
        for decision in [DecisionTag::Denied, DecisionTag::RejectedByPolicy] {
            let f = fact(
                TaintSet::pristine(),
                IdentityRef::new(5),
                ProcessId::new(1),
                1,
                decision,
            );
            assert_eq!(
                AuditRules::default().tags_for(&f, 0),
                vec![AuditTag::CrossIdentity]
            );
        }
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
            DecisionTag::DriverError,
        );
        let rules = AuditRules {
            alert_on_decisions: vec!["driver_error".into()],
            ..Default::default()
        };
        assert!(rules.tags_for(&f, 0).contains(&AuditTag::Alert {
            rule: "driver_error".into()
        }));
    }

    fn gateway_fact(event: &str) -> Fact {
        let mut f = fact(
            TaintSet::author(),
            IdentityRef::ROOT,
            ProcessId::new(1),
            0,
            DecisionTag::Ok,
        );
        f.id.invocation = InvocationId::new(0);
        f.id.position = GATEWAY_AUDIT_NODE;
        f.handle = HandleId::new(0, 0);
        f.replay = ReplayClass::Observation;
        f.outcome = Some(Value::map(alloc::collections::BTreeMap::from([
            ("event".into(), Value::from(event)),
            ("outcome".into(), Value::from("accepted")),
        ])));
        f
    }

    #[test]
    fn gateway_events_use_application_labels_without_a_prefix_registry() {
        for event in ["console_login", "gateway_mcp", "host.work_completed"] {
            let f = gateway_fact(event);
            assert_eq!(gateway_audit_event(&f), Some(event));
            assert_eq!(
                AuditRules::default().tags_for(&f, 0),
                vec![AuditTag::Custom {
                    label: event.into()
                }]
            );
        }
    }

    #[test]
    fn operation_results_and_lifecycle_events_cannot_impersonate_gateway_audits() {
        for event in ["console_login", "gateway_mcp", "host.work_completed"] {
            let mut operation = gateway_fact(event);
            operation.id.invocation = InvocationId::new(1);
            operation.handle = HandleId::new(0, 1);
            operation.resource = ResourceId::new(1);
            // Even a legal graph at the same source position has a nonzero
            // dynamic invocation and an active handle, not an audit envelope.
            assert!(AuditRules::default().tags_for(&operation, 0).is_empty());
            operation.id.position = NodeId::ROOT;
            assert!(AuditRules::default().tags_for(&operation, 0).is_empty());

            let mut lifecycle = gateway_fact(event);
            lifecycle.id.position = NodeId::new(u32::MAX);
            assert!(AuditRules::default().tags_for(&lifecycle, 0).is_empty());
        }
    }

    #[test]
    fn gateway_audit_requires_the_complete_administrative_record() {
        let corruptions: &[fn(&mut Fact)] = &[
            |fact| fact.schema_version += 1,
            |fact| fact.id.position = NodeId::ROOT,
            |fact| fact.id.invocation = InvocationId::new(1),
            |fact| fact.id.attempt = 1,
            |fact| fact.id.process = ProcessId::new(2),
            |fact| fact.caller_identity = None,
            |fact| fact.caller_identity = Some(IdentityRef::new(2)),
            |fact| fact.acting = IdentityRef::new(2),
            |fact| fact.handle = HandleId::new(0, 1),
            |fact| fact.resource = ResourceId::new(1),
            |fact| fact.method = MethodId::new(1),
            |fact| fact.input = Value::integer(1),
            |fact| fact.taint = TaintSet::pristine(),
            |fact| fact.decision = DecisionTag::Denied,
            |fact| fact.replay = ReplayClass::Deterministic,
            |fact| {
                fact.batch = Some(crate::BatchSummary {
                    elements: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                    input_summary: Value::null(),
                    output_summary: Value::null(),
                })
            },
            |fact| fact.outcome = None,
            |fact| fact.outcome = Some(Value::null()),
        ];
        for (index, corrupt) in corruptions.iter().enumerate() {
            let mut f = gateway_fact("host.work_completed");
            corrupt(&mut f);
            assert!(gateway_audit_event(&f).is_none(), "corruption {index}");
        }
    }

    #[test]
    fn gateway_audit_rejects_missing_malformed_and_unknown_envelope_fields() {
        use alloc::collections::BTreeMap;
        let valid = BTreeMap::from([
            ("event".into(), Value::from("host.work_completed")),
            ("outcome".into(), Value::from("accepted")),
        ]);
        for key in ["event", "outcome"] {
            let mut f = gateway_fact("host.work_completed");
            let mut missing = valid.clone();
            missing.remove(key);
            f.outcome = Some(Value::map(missing));
            assert!(gateway_audit_event(&f).is_none(), "missing {key}");
            for value in [Value::integer(2), Value::from("")] {
                let mut fields = valid.clone();
                fields.insert(key.into(), value);
                f.outcome = Some(Value::map(fields));
                assert!(gateway_audit_event(&f).is_none(), "invalid {key}");
            }
        }
        for (key, value) in [
            ("username", Value::integer(2)),
            ("source_addr", Value::null()),
            ("unknown", Value::from("extension")),
        ] {
            let mut fields = valid.clone();
            fields.insert(key.into(), value);
            let mut f = gateway_fact("host.work_completed");
            f.outcome = Some(Value::map(fields));
            assert!(gateway_audit_event(&f).is_none(), "invalid {key}");
        }
        // Extension metadata is explicitly nested; its schema belongs to the
        // application, including keys that also occur in the common envelope.
        let mut fields = valid.clone();
        fields.insert("details".into(), Value::map(valid));
        let mut f = gateway_fact("host.work_completed");
        f.outcome = Some(Value::map(fields));
        assert_eq!(gateway_audit_event(&f), Some("host.work_completed"));
    }
}
