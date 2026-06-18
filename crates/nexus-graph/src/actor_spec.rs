//! Actor declarations and capability linting.
//!
//! An [`ActorSpec`] names a long-lived [`DoNode`] body and declares the
//! capabilities, state paths, subscriptions, and budget attached to that body.
//! [`lint`] compares operations found in the body with the declared capability
//! literals.

use crate::r#do::DoNode;
use nexus_types::{BudgetSpec, CapSet, Capability};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Declaration for a named long-lived `Do<()>` body.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorSpec {
    /// Stable actor name.
    #[serde(default)]
    pub name: String,
    /// Capability literals declared for the actor body.
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    /// State path patterns declared for reads and writes.
    #[serde(default)]
    pub declared_states: Vec<String>,
    /// Stream path patterns the actor subscribes to.
    #[serde(default)]
    pub subscriptions: Vec<String>,
    /// Granted capability set.
    #[serde(default)]
    pub capabilities: CapSet,
    /// Budget and inflight limits.
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
        let Ok(path) = nexus_types::Path::parse(target) else {
            return false;
        };
        for literal in &self.declared_capabilities {
            let cap = match Capability::parse(literal) {
                Ok(cap) => cap,
                Err(_) => return false,
            };
            if cap.covers(verb, &path) {
                return true;
            }
        }
        false
    }
}

/// The severity of a [`LintFinding`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    /// Security-relevant: the program would exceed the declared ceiling at
    /// runtime.
    Error,
    /// Advisory only.
    Warning,
}

/// One issue found by [`lint`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LintFinding {
    /// Severity assigned to this finding.
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

/// Lint a program's AST against its [`ActorSpec`].
///
/// Flags every capability the program **uses but does not declare**. These are
/// security-relevant because `declared_capabilities` forms the runtime ceiling:
/// an undeclared capability is outside the attenuated task-level Handle set and
/// would be denied. A fully-declared program yields no findings.
///
/// Each distinct undeclared `(target, method)` produces one finding. Declared
/// capabilities that the program never uses are *not* flagged here —
/// over-declaring only widens the ceiling, a separate (advisory) concern.
pub fn lint(spec: &ActorSpec, program: &DoNode) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    let mut declared = Vec::new();
    for literal in &spec.declared_capabilities {
        match Capability::parse(literal) {
            Ok(capability) => declared.push(capability),
            Err(error) => findings.push(LintFinding {
                severity: LintSeverity::Error,
                target: literal.clone(),
                verb: String::new(),
                method: "declared_capabilities".into(),
                message: format!("declared capability `{literal}` is malformed: {error}"),
            }),
        }
    }
    let mut seen = HashSet::new();
    for op in program.ops() {
        let target_path = op.target.path();
        let target = target_path.to_string();
        let verb = capability_verb_for_method(&op.method);
        if declared.iter().any(|cap| cap.covers(verb, target_path)) {
            continue;
        }
        let key = (target.clone(), op.method.clone());
        if !seen.insert(key) {
            continue;
        }
        findings.push(LintFinding {
            severity: LintSeverity::Error,
            target: target.clone(),
            verb: verb.into(),
            method: op.method.clone(),
            message: format!(
                "capability `{verb}://{}` for method `{}` is used but not declared in \
                 ActorSpec.declared_capabilities; it exceeds the task-level ceiling",
                capability_target(&target),
                op.method
            ),
        });
    }
    findings
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
    use anyhow::{Context, anyhow, ensure};
    use nexus_types::{OutputMode, Path, ProcessId, ResourceName, Value};

    fn s(name: &str) -> StepRef {
        StepRef::new(ProcessId::new(1), name)
    }

    fn op(path: &str) -> anyhow::Result<OperationTemplate> {
        Ok(OperationTemplate {
            target: ResourceName::new(
                Path::parse(path)
                    .map_err(|error| anyhow!("path parse failed for {path}: {error}"))?,
            ),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        })
    }

    #[test]
    fn undeclared_capability_is_flagged() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities("notifier", ["perform://effect/events/emit"]);
        let program = DoNode::r#let(
            "e",
            DoNode::op(op("effect://events/emit")?),
            DoNode::op(op("effect://fetch/get")?),
        );
        let findings = lint(&spec, &program);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        let finding = findings.first().context("missing finding")?;
        ensure!(
            finding.target == "effect://fetch/get",
            "unexpected target: {}",
            finding.target
        );
        ensure!(
            finding.verb == "perform",
            "unexpected verb: {}",
            finding.verb
        );
        ensure!(
            finding.severity == LintSeverity::Error,
            "unexpected severity: {:?}",
            finding.severity
        );
        Ok(())
    }

    #[test]
    fn fully_declared_program_is_clean() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities(
            "housekeeper",
            ["perform://effect/fs/read", "perform://effect/events/emit"],
        );
        let program = DoNode::Both(
            Box::new(DoNode::op(op("effect://fs/read")?)),
            Box::new(DoNode::op(op("effect://events/emit")?)),
        );
        let findings = lint(&spec, &program);
        ensure!(findings.is_empty(), "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn capability_prefix_covers_finer_target() -> anyhow::Result<()> {
        ensure!(
            capability_covers("perform://effect/fs/**", "perform", "effect://fs/read"),
            "wildcard capability did not cover finer target"
        );
        ensure!(
            capability_covers("perform://effect/fs/read", "perform", "effect://fs/read"),
            "exact capability did not cover target"
        );
        ensure!(
            !capability_covers("perform://effect/fs/read", "perform", "effect://fs"),
            "finer target covered coarser target"
        );
        ensure!(
            !capability_covers("perform://effect/fs/**", "perform", "effect://fetch/get"),
            "capability covered different namespace"
        );
        ensure!(
            !capability_covers("effect://fs", "perform", "effect://fs/read"),
            "resource path was treated as capability literal"
        );
        Ok(())
    }

    #[test]
    fn duplicate_undeclared_uses_collapse_to_one_finding() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities("a", ["perform://effect/memory/**"]);
        let program = DoNode::Both(
            Box::new(DoNode::op(op("effect://x/post")?)),
            Box::new(DoNode::op(op("effect://x/post")?)),
        );
        let findings = lint(&spec, &program);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn malformed_declared_capability_is_flagged() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities("a", ["effect://x/post"]);
        let findings = lint(&spec, &DoNode::pure(Value::Null));

        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        let finding = findings.first().context("missing finding")?;
        ensure!(
            finding.target == "effect://x/post",
            "unexpected target: {}",
            finding.target
        );
        ensure!(
            finding.method == "declared_capabilities",
            "unexpected method: {}",
            finding.method
        );
        ensure!(
            finding.severity == LintSeverity::Error,
            "unexpected severity: {:?}",
            finding.severity
        );
        ensure!(
            !spec.declares_capability("perform", "effect://x/post"),
            "malformed declaration should not grant capability"
        );
        Ok(())
    }

    #[test]
    fn state_append_requires_write_capability() -> anyhow::Result<()> {
        let mut append = op("state://events/topic")?;
        append.method = "append".into();
        let program = DoNode::op(append);

        let read_spec = ActorSpec::with_capabilities("reader", ["read://state/events/**"]);
        let findings = lint(&read_spec, &program);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        let finding = findings.first().context("missing finding")?;
        ensure!(finding.verb == "write", "unexpected verb: {}", finding.verb);
        ensure!(
            finding
                .message
                .contains("capability `write://state/events/topic`"),
            "unexpected message: {}",
            finding.message
        );

        let write_spec = ActorSpec::with_capabilities("writer", ["write://state/events/**"]);
        let findings = lint(&write_spec, &program);
        ensure!(findings.is_empty(), "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn pure_program_with_no_ops_is_clean() -> anyhow::Result<()> {
        let spec = ActorSpec::default();
        let program = DoNode::pure(Value::Int(1)).and_then(s("noop"));
        let findings = lint(&spec, &program);
        ensure!(findings.is_empty(), "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn spec_serde_roundtrip() -> anyhow::Result<()> {
        let spec = ActorSpec {
            name: "n".into(),
            declared_capabilities: vec!["perform://effect/fs/**".into()],
            declared_states: vec!["state://memory/alice/*".into()],
            subscriptions: vec!["state://events/external/chat_bridge/source".into()],
            capabilities: CapSet::new(),
            budget: BudgetSpec::default(),
        };
        let s = serde_json::to_string(&spec)?;
        let back: ActorSpec = serde_json::from_str(&s)?;
        ensure!(spec == back, "round trip changed spec: {back:?}");
        Ok(())
    }
}
