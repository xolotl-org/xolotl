//! `ActorSpec` + linter (§20.2, §21.5) — declared vs. actually-used capabilities.
//!
//! An **Actor** is a named, long-lived Process whose body is a `Do<()>` (§20.2).
//! An [`ActorSpec`] is the lintable declaration wrapper around that body: it
//! declares the capabilities / state paths / subscriptions / budget the Actor
//! intends to touch, so an operator can know what the Actor reaches *without
//! reading its code* (§20.2).
//!
//! The declaration is more than documentation. Per §21.5(2), an Actor's
//! `declared_capabilities` is promoted from a lint hint to a **runtime ceiling**:
//! when a Process begins handling untrusted input, the kernel derives an
//! attenuated child-Handle set covering only the declared capabilities, so an
//! injected Plan cannot reach a capability the task never declared. That makes the
//! security-relevant lint finding the **undeclared-but-used** capability: an
//! Operation the program issues against a target the spec did not declare would,
//! at runtime, be outside the task ceiling.
//!
//! [`lint`] walks a program's AST via [`DoNode::ops`](crate::r#do::DoNode::ops)
//! and compares each Operation's required capability against the declared
//! capability literals.

use crate::r#do::DoNode;
use crate::graph::OperationTemplate;
use nexus_types::{BudgetSpec, CapSet, Capability};
use serde::{Deserialize, Serialize};

/// The lintable declaration around an Actor's `Do<()>` body (§20.2). Standard
/// Actors ship unprivileged and version-aligned with the runtime; this spec is
/// what an operator (or `nexus-console`) reads to audit reach.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorSpec {
    /// A stable name for the Actor (`process://<identity>/<name>`, §20.3).
    #[serde(default)]
    pub name: String,
    /// Capability literals the Actor declares it may use. These are canonical
    /// §21.1 capability strings such as `perform://effect/x/post`,
    /// `read://state/memory/alice/**`, and `subscribe://state/chat/**`. This
    /// list is **also** the §21.5 task-level capability ceiling.
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    /// `state://…` path patterns the Actor declares it will read/write.
    #[serde(default)]
    pub declared_states: Vec<String>,
    /// Stream paths the Actor subscribes to (compiled into a `for_each`
    /// Reaction, §20.4).
    #[serde(default)]
    pub subscriptions: Vec<String>,
    /// The capability set the Actor is granted; the operator checks declared
    /// capabilities are covered by these Grants (§20.2).
    #[serde(default)]
    pub capabilities: CapSet,
    /// Cost / inflight ceiling for the Actor (§21.2).
    #[serde(default)]
    pub budget: BudgetSpec,
}

impl ActorSpec {
    /// A spec declaring only a name and a set of capability literals.
    pub fn with_capabilities<I, S>(name: impl Into<String>, capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.into(),
            declared_capabilities: capabilities.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Whether `(verb, target)` is covered by any declared capability literal.
    pub fn declares_capability(&self, verb: &str, target: &str) -> bool {
        self.declared_capabilities
            .iter()
            .any(|literal| capability_covers(literal, verb, target))
    }
}

/// The severity of a [`LintFinding`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    /// Security-relevant: the program would exceed the declared ceiling at
    /// runtime (§21.5(2)).
    Error,
    /// Advisory only.
    Warning,
}

/// One issue found by [`lint`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LintFinding {
    pub severity: LintSeverity,
    /// The operation target the finding is about.
    pub target: String,
    /// The capability verb required for that operation.
    pub verb: String,
    /// The method invoked on that target (context for the operator).
    pub method: String,
    /// Human-readable explanation.
    pub message: String,
}

/// Lint a program's AST against its [`ActorSpec`] (§20.2 / §21.5).
///
/// Flags every capability the program **uses but does not declare** — these are
/// the security-relevant ones, because §21.5(2) makes `declared_capabilities`
/// the runtime ceiling: an undeclared capability would be outside the attenuated
/// task-level Handle set and would be denied (or, if the ceiling were not
/// enforced, would be an unaudited reach). A fully-declared program yields no
/// findings.
///
/// Each distinct undeclared `(target, method)` produces one finding. Declared
/// capabilities that the program never uses are *not* flagged here —
/// over-declaring only widens the ceiling, a separate (advisory) concern.
pub fn lint(spec: &ActorSpec, program: &DoNode) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    let mut seen: Vec<(String, String)> = Vec::new();
    for op in program.ops() {
        let target = op_target(op);
        let verb = capability_verb_for_method(&op.method);
        if spec.declares_capability(verb, &target) {
            continue;
        }
        let key = (target.clone(), op.method.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        findings.push(LintFinding {
            severity: LintSeverity::Error,
            target: target.clone(),
            verb: verb.into(),
            method: op.method.clone(),
            message: format!(
                "capability `{verb}://{}` for method `{}` is used but not declared in \
                 ActorSpec.declared_capabilities; it exceeds the §21.5 task-level ceiling",
                capability_target(&target),
                op.method
            ),
        });
    }
    findings
}

/// The target path string of an Operation template.
fn op_target(op: &OperationTemplate) -> String {
    op.target.path().to_string()
}

/// Whether a declared capability literal covers the required `(verb, target)`.
pub fn capability_covers(literal: &str, verb: &str, target: &str) -> bool {
    let Ok(cap) = Capability::parse(literal) else {
        return false;
    };
    let Ok(path) = nexus_types::Path::parse(target) else {
        return false;
    };
    cap.covers(verb, &path)
}

fn capability_verb_for_method(method: &str) -> &'static str {
    match method {
        "read" | "list" => "read",
        "write" | "append" | "delete" => "write",
        "subscribe" => "subscribe",
        _ => "perform",
    }
}

fn capability_target(target: &str) -> String {
    target.replacen("://", "/", 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{OperationTemplate, StepRef};
    use nexus_types::{OutputMode, Path, ProcessId, ResourceName, Value};

    fn s(name: &str) -> StepRef {
        StepRef::new(ProcessId::new(1), name)
    }

    fn op(path: &str) -> OperationTemplate {
        OperationTemplate {
            target: ResourceName::new(Path::parse(path).unwrap()),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        }
    }

    #[test]
    fn undeclared_capability_is_flagged() {
        let spec = ActorSpec::with_capabilities("notifier", ["perform://effect/events/emit"]);
        // Program declares events but reaches out to fetch — undeclared.
        let program = DoNode::r#let(
            "e",
            DoNode::op(op("effect://events/emit")),
            DoNode::op(op("effect://fetch/get")),
        );
        let findings = lint(&spec, &program);
        assert_eq!(findings.len(), 1, "only the undeclared fetch is flagged");
        assert_eq!(findings[0].target, "effect://fetch/get");
        assert_eq!(findings[0].verb, "perform");
        assert_eq!(findings[0].severity, LintSeverity::Error);
    }

    #[test]
    fn fully_declared_program_is_clean() {
        let spec = ActorSpec::with_capabilities(
            "housekeeper",
            ["perform://effect/fs/read", "perform://effect/events/emit"],
        );
        let program = DoNode::Both(
            Box::new(DoNode::op(op("effect://fs/read"))),
            Box::new(DoNode::op(op("effect://events/emit"))),
        );
        assert!(
            lint(&spec, &program).is_empty(),
            "every used effect is declared"
        );
    }

    #[test]
    fn capability_prefix_covers_finer_target() {
        assert!(capability_covers(
            "perform://effect/fs/**",
            "perform",
            "effect://fs/read"
        ));
        assert!(capability_covers(
            "perform://effect/fs/read",
            "perform",
            "effect://fs/read"
        ));
        // Not a prefix: a finer pattern does not cover a coarser target.
        assert!(!capability_covers(
            "perform://effect/fs/read",
            "perform",
            "effect://fs"
        ));
        // Different namespace.
        assert!(!capability_covers(
            "perform://effect/fs/**",
            "perform",
            "effect://fetch/get"
        ));
        // Resource paths are not capability literals.
        assert!(!capability_covers(
            "effect://fs",
            "perform",
            "effect://fs/read"
        ));
    }

    #[test]
    fn duplicate_undeclared_uses_collapse_to_one_finding() {
        let spec = ActorSpec::with_capabilities("a", ["perform://effect/memory/**"]);
        let program = DoNode::Both(
            Box::new(DoNode::op(op("effect://x/post"))),
            Box::new(DoNode::op(op("effect://x/post"))),
        );
        let findings = lint(&spec, &program);
        assert_eq!(findings.len(), 1, "same (target,method) flagged once");
    }

    #[test]
    fn state_append_requires_write_capability() {
        let mut append = op("state://events/topic");
        append.method = "append".into();
        let program = DoNode::op(append);

        let read_spec = ActorSpec::with_capabilities("reader", ["read://state/events/**"]);
        let findings = lint(&read_spec, &program);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].verb, "write");
        assert!(
            findings[0]
                .message
                .contains("capability `write://state/events/topic`"),
            "message should point operators to the canonical write capability"
        );

        let write_spec = ActorSpec::with_capabilities("writer", ["write://state/events/**"]);
        assert!(lint(&write_spec, &program).is_empty());
    }

    #[test]
    fn pure_program_with_no_ops_is_clean() {
        let spec = ActorSpec::default();
        let program = DoNode::pure(Value::Int(1)).and_then(s("noop"));
        assert!(lint(&spec, &program).is_empty());
    }

    #[test]
    fn spec_serde_roundtrip() {
        let spec = ActorSpec {
            name: "n".into(),
            declared_capabilities: vec!["perform://effect/fs/**".into()],
            declared_states: vec!["state://memory/alice/*".into()],
            subscriptions: vec!["state://events/extensions/chat_bridge/source".into()],
            capabilities: CapSet::new(),
            budget: BudgetSpec::default(),
        };
        let s = serde_json::to_string(&spec).unwrap();
        let back: ActorSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(spec, back);
    }
}
